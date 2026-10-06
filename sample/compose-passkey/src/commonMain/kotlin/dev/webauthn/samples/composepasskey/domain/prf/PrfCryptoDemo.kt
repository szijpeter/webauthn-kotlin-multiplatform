package dev.webauthn.samples.composepasskey.domain.prf

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.prf.PrfCiphertext
import dev.webauthn.client.prf.PrfCryptoClient
import dev.webauthn.client.prf.PrfCryptoSession
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyError
import dev.webauthn.samples.composepasskey.domain.passkey.userGuidance
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import kotlin.random.Random

private const val PRF_SALT_LENGTH_BYTES: Int = 32
private const val SAMPLE_PRF_CONTEXT: String = "samples.compose-passkey.prf.v1"
private const val SAMPLE_ASSOCIATED_DATA: String = "samples-compose-passkey"

sealed interface PrfCryptoDemoSessionState {
    data object NoSession : PrfCryptoDemoSessionState

    data object SessionReady : PrfCryptoDemoSessionState

    data object CiphertextReady : PrfCryptoDemoSessionState
}

internal sealed interface PrfDemoResult {
    val message: String

    data class Success(
        override val message: String,
        val plaintext: String? = null,
    ) : PrfDemoResult

    data class Failure(override val message: String) : PrfDemoResult
}

internal interface PrfSaltStore {
    fun loadOrCreate(key: String): Base64UrlBytes
}

internal class InMemoryPrfSaltStore : PrfSaltStore {
    private val salts: MutableMap<String, Base64UrlBytes> = mutableMapOf()

    override fun loadOrCreate(key: String): Base64UrlBytes {
        return salts.getOrPut(key) {
            Base64UrlBytes.fromBytes(Random.nextBytes(PRF_SALT_LENGTH_BYTES))
        }
    }
}

@OptIn(ExperimentalWebAuthnL3Api::class)
internal class PrfCryptoDemoController(
    passkeyClient: PasskeyClient,
    private val backend: DemoPasskeyBackend,
    private val saltStore: PrfSaltStore,
    private val isForeground: () -> Boolean = { true },
) {
    private val prfCryptoClient: PrfCryptoClient = PrfCryptoClient(passkeyClient)
    private var internalState: SessionDataState = SessionDataState.NoSession
    private var operationGeneration: Long = 0
    private var promptGeneration: Long? = null

    val isPlatformPromptInProgress: Boolean
        get() = promptGeneration == operationGeneration

    val sessionState: PrfCryptoDemoSessionState
        get() = internalState.publicState

    @Suppress("CyclomaticComplexMethod")
    suspend fun signInWithPrf(config: PasskeyDemoConfig, supportsPrf: Boolean): PrfDemoResult {
        if (!supportsPrf) {
            return PrfDemoResult.Failure("This device does not report PRF support.")
        }
        val generation = ++operationGeneration
        val saltScope = "${config.rpId}:${config.userHandle}"
        val firstSalt = saltStore.loadOrCreate(saltScope)
        val startPayload = config.toAuthenticationStartPayload(prfSalt = firstSalt)
        val startResult = runSuspendCatching {
            backend.authentication.start(startPayload)
        }.getOrElse { _ ->
            return PrfDemoResult.Failure(
                "Could not start passkey sign-in. Check the server configuration and connection, then try again.",
            )
        }
        if (generation != operationGeneration || !isForeground()) return cancelledResult()
        val signInOptions = startResult.options
        promptGeneration = generation
        val assertion = try {
            prfCryptoClient.authenticateWithPrf(
                options = signInOptions,
                salts = AuthenticationExtensionsPRFValues(first = firstSalt),
                context = SAMPLE_PRF_CONTEXT,
            )
        } finally {
            if (promptGeneration == generation) promptGeneration = null
        }
        val authResult = when (assertion) {
            is PasskeyResult.Failure -> return PrfDemoResult.Failure(
                DemoCeremonyError.Platform(assertion.error).userGuidance(),
            )
            is PasskeyResult.Success -> assertion.value
        }
        var sessionTransferred = false
        try {
            if (generation != operationGeneration || !isForeground()) return cancelledResult()
            val finishResult = runSuspendCatching {
                backend.authentication.finish(startResult.state, authResult.response)
            }.getOrElse { _ ->
                return PrfDemoResult.Failure(
                    "Could not verify passkey sign-in. Start a new request to try again.",
                )
            }
            if (generation != operationGeneration || !isForeground()) return cancelledResult()
            return when (finishResult) {
                DefaultPasskeyFinishResult.Verified -> {
                    transitionTo(SessionDataState.SessionReady(authResult.session))
                    sessionTransferred = true
                    PrfDemoResult.Success(
                        message = "PRF session ready. Caller-owned salt is available.",
                    )
                }

                is DefaultPasskeyFinishResult.Rejected -> {
                    PrfDemoResult.Failure(
                        "PRF sign-in verification rejected. Start a new sign-in request.",
                    )
                }
            }
        } finally {
            if (!sessionTransferred) {
                authResult.session.clear()
            }
        }
    }

    suspend fun encrypt(plaintext: String): PrfDemoResult {
        val activeSession = internalState.sessionOrNull()
            ?: return PrfDemoResult.Failure("No PRF session. Run Sign In + PRF first.")
        if (plaintext.isBlank()) {
            return PrfDemoResult.Failure("Enter plaintext before encryption.")
        }
        val generation = operationGeneration
        return runSuspendCatching {
            val ciphertext = activeSession.encryptString(
                plaintext = plaintext,
                associatedData = SAMPLE_ASSOCIATED_DATA.encodeToByteArray(),
            )
            if (generation != operationGeneration || !isForeground()) return cancelledResult()
            transitionTo(SessionDataState.CiphertextReady(activeSession, ciphertext))
            PrfDemoResult.Success(
                message = "Encrypted ${plaintext.length} chars to ${ciphertext.ciphertext.bytes().size} bytes.",
            )
        }.getOrElse { _ ->
            PrfDemoResult.Failure("Could not encrypt the message. Unlock a session and try again.")
        }
    }

    suspend fun decrypt(): PrfDemoResult {
        val generation = operationGeneration
        return when (val state = internalState) {
            SessionDataState.NoSession -> PrfDemoResult.Failure("No PRF session. Run Sign In + PRF first.")
            is SessionDataState.SessionReady -> PrfDemoResult.Failure("No ciphertext. Encrypt text first.")
            is SessionDataState.CiphertextReady -> runSuspendCatching {
                val plaintext = state.session.decryptToString(state.payload)
                if (generation != operationGeneration || !isForeground()) return cancelledResult()
                PrfDemoResult.Success(
                    message = "Decrypt succeeded.",
                    plaintext = plaintext,
                )
            }.getOrElse { _ ->
                PrfDemoResult.Failure(
                    "Could not decrypt the message. Check that you used the same passkey and saved data.",
                )
            }
        }
    }

    fun clearSession(): PrfDemoResult {
        operationGeneration += 1
        return lockCurrentSession()
    }

    // Backgrounding during an OS prompt clears the previous key without cancelling the prompt.
    fun lockCurrentSession(): PrfDemoResult {
        return when (internalState) {
            SessionDataState.NoSession -> PrfDemoResult.Success("No active PRF session.")
            is SessionDataState.SessionReady, is SessionDataState.CiphertextReady -> {
                transitionTo(SessionDataState.NoSession)
                PrfDemoResult.Success("PRF session key cleared from memory.")
            }
        }
    }

    private fun cancelledResult(): PrfDemoResult.Failure =
        PrfDemoResult.Failure("Session cleared. Use your passkey to continue.")

    private fun transitionTo(newState: SessionDataState) {
        val previousSession = internalState.sessionOrNull()
        val nextSession = newState.sessionOrNull()
        if (previousSession !== nextSession) {
            previousSession?.clear()
        }
        internalState = newState
    }

    private val SessionDataState.publicState: PrfCryptoDemoSessionState
        get() = when (this) {
            SessionDataState.NoSession -> PrfCryptoDemoSessionState.NoSession
            is SessionDataState.SessionReady -> PrfCryptoDemoSessionState.SessionReady
            is SessionDataState.CiphertextReady -> PrfCryptoDemoSessionState.CiphertextReady
        }

    private fun SessionDataState.sessionOrNull(): PrfCryptoSession? {
        return when (this) {
            SessionDataState.NoSession -> null
            is SessionDataState.SessionReady -> session
            is SessionDataState.CiphertextReady -> session
        }
    }

    private sealed interface SessionDataState {
        data object NoSession : SessionDataState

        data class SessionReady(
            val session: PrfCryptoSession,
        ) : SessionDataState

        data class CiphertextReady(
            val session: PrfCryptoSession,
            val payload: PrfCiphertext,
        ) : SessionDataState
    }
}
