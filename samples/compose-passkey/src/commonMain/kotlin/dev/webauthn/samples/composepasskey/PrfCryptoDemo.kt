package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.client.prf.PrfCryptoClient
import dev.webauthn.client.prf.PrfCryptoSession
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import kotlin.random.Random

private const val PRF_SALT_LENGTH_BYTES: Int = 32
private const val SAMPLE_PRF_CONTEXT: String = "samples.compose-passkey.prf.v1"
private const val SAMPLE_ASSOCIATED_DATA: String = "samples-compose-passkey"

internal sealed interface PrfDemoResult {
    data class Success(
        val message: String,
        val plaintext: String? = null,
    ) : PrfDemoResult

    data class Failure(val message: String) : PrfDemoResult
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
    private val serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
    private val saltStore: PrfSaltStore,
) {
    private val prfCryptoClient: PrfCryptoClient = PrfCryptoClient(passkeyClient)
    private var session: PrfCryptoSession? = null
    private var encryptedPayload: dev.webauthn.client.prf.PrfCiphertext? = null

    val hasSession: Boolean
        get() = session != null

    val hasEncryptedPayload: Boolean
        get() = encryptedPayload != null

    @Suppress("CyclomaticComplexMethod")
    suspend fun signInWithPrf(config: PasskeyDemoConfig, supportsPrf: Boolean): PrfDemoResult {
        if (!supportsPrf) {
            return PrfDemoResult.Failure("This device does not report PRF support.")
        }
        val saltScope = "${config.rpId}:${config.userHandle}"
        val firstSalt = saltStore.loadOrCreate(saltScope)
        val startPayload = config.toAuthenticationStartPayload(prfSalt = firstSalt)
        val signInOptions = when (
            val startResult = runCatching { serverClient.getSignInOptions(startPayload) }
                .getOrElse { throwable ->
                    return PrfDemoResult.Failure(
                        "PRF sign-in start failed: ${throwable.message ?: "unknown error"}",
                    )
                }
        ) {
            is dev.webauthn.model.ValidationResult.Invalid -> {
                val details = startResult.errors.joinToString("; ") { "${it.field}: ${it.message}" }
                return PrfDemoResult.Failure("PRF sign-in start failed: $details")
            }

            is dev.webauthn.model.ValidationResult.Valid -> startResult.value
        }
        val authResult = when (
            val assertionResult = prfCryptoClient.authenticateWithPrf(
                options = signInOptions,
                firstSalt = firstSalt,
                context = SAMPLE_PRF_CONTEXT,
            )
        ) {
            is PasskeyResult.Failure -> {
                return PrfDemoResult.Failure("PRF assertion failed: ${assertionResult.error.message}")
            }

            is PasskeyResult.Success -> assertionResult.value
        }
        val finishResult = runCatching {
            serverClient.finishSignIn(
                params = startPayload,
                response = authResult.response,
                challengeAsBase64Url = signInOptions.challenge.value.encoded(),
            )
        }.getOrElse { throwable ->
            return PrfDemoResult.Failure(
                "PRF sign-in finish failed: ${throwable.message ?: "unknown error"}",
            )
        }
        return when (finishResult) {
            PasskeyFinishResult.Verified -> {
                session?.clear()
                session = authResult.session
                encryptedPayload = null
                PrfDemoResult.Success(
                    message = "PRF session ready (${authResult.session.keyFingerprint}). Caller-owned salt loaded for $saltScope.",
                )
            }

            is PasskeyFinishResult.Rejected -> {
                PrfDemoResult.Failure(
                    "PRF sign-in verification rejected: ${finishResult.message ?: "server rejected response"}",
                )
            }
        }
    }

    suspend fun encrypt(plaintext: String): PrfDemoResult {
        val activeSession = session ?: return PrfDemoResult.Failure("No PRF session. Run Sign In + PRF first.")
        if (plaintext.isBlank()) {
            return PrfDemoResult.Failure("Enter plaintext before encryption.")
        }
        return runCatching {
            val ciphertext = activeSession.encryptString(
                plaintext = plaintext,
                associatedData = SAMPLE_ASSOCIATED_DATA.encodeToByteArray(),
            )
            encryptedPayload = ciphertext
            PrfDemoResult.Success(
                message = "Encrypted ${plaintext.length} chars to ${ciphertext.ciphertext.bytes().size} bytes.",
            )
        }.getOrElse { throwable ->
            PrfDemoResult.Failure("Encrypt failed: ${throwable.message ?: "unknown error"}")
        }
    }

    suspend fun decrypt(): PrfDemoResult {
        val activeSession = session ?: return PrfDemoResult.Failure("No PRF session. Run Sign In + PRF first.")
        val payload = encryptedPayload ?: return PrfDemoResult.Failure("No ciphertext. Encrypt text first.")
        return runCatching {
            val plaintext = activeSession.decryptToString(payload)
            PrfDemoResult.Success(
                message = "Decrypt succeeded.",
                plaintext = plaintext,
            )
        }.getOrElse { throwable ->
            PrfDemoResult.Failure("Decrypt failed: ${throwable.message ?: "unknown error"}")
        }
    }

    fun clearSession(): PrfDemoResult {
        val activeSession = session
        return if (activeSession == null) {
            PrfDemoResult.Success("No active PRF session.")
        } else {
            activeSession.clear()
            session = null
            encryptedPayload = null
            PrfDemoResult.Success("PRF session key cleared from memory.")
        }
    }
}
