@file:OptIn(ExperimentalWebAuthnL3Api::class)

package dev.webauthn.samples.composepasskey

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.domain.prf.PrfDemoResult
import dev.webauthn.samples.composepasskey.domain.prf.PrfSaltStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PrfCryptoDemoControllerTest {
    @Test
    fun signInWithPrf_returnsUnsupported_whenCapabilityDisabled() = runTest {
        val server = PrfTestServerClient()
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val result = controller.signInWithPrf(prfDemoConfig(), supportsPrf = false)

        assertIs<PrfDemoResult.Failure>(result)
        assertTrue(result.message.contains("does not report PRF support"))
        assertEquals(0, server.signInStartCalls)
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun signInWithPrf_success_then_encryptDecrypt_roundtrip() = runTest {
        val saltStore = FixedSaltStore()
        val server = PrfTestServerClient()
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = saltStore,
        )

        val signInResult = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        assertIs<PrfDemoResult.Success>(signInResult)
        assertEquals(PrfCryptoDemoSessionState.SessionReady, controller.sessionState)
        assertNotNull(server.lastAuthenticationStartPayload)
        assertEquals(
            saltStore.salt.encoded(),
            server.lastAuthenticationStartPayload?.extensions?.prf?.eval?.first,
        )
        assertEquals(
            saltStore.salt.encoded(),
            passkeyClient.lastAssertionOptions?.extensions?.prf?.eval?.first?.encoded(),
        )

        val encryptResult = controller.encrypt("hello prf")
        assertIs<PrfDemoResult.Success>(encryptResult)
        assertEquals(PrfCryptoDemoSessionState.CiphertextReady, controller.sessionState)

        val decryptResult = controller.decrypt()
        assertIs<PrfDemoResult.Success>(decryptResult)
        assertEquals("hello prf", decryptResult.plaintext)

        controller.clearSession()
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun decrypt_requiresCiphertext_afterSessionIsReady() = runTest {
        val server = PrfTestServerClient()
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val signInResult = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        assertIs<PrfDemoResult.Success>(signInResult)
        assertEquals(PrfCryptoDemoSessionState.SessionReady, controller.sessionState)

        val decryptResult = controller.decrypt()
        val failure = assertIs<PrfDemoResult.Failure>(decryptResult)
        assertTrue(failure.message.contains("No ciphertext. Encrypt text first."))
    }

    @Test
    fun signInWithPrf_rejectedFinish_returnsFailure() = runTest {
        val server = PrfTestServerClient(signInVerifyResult = false)
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val result = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)

        assertIs<PrfDemoResult.Failure>(result)
        assertTrue(result.message.contains("rejected"))
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun signInWithPrf_usesStableSaltScope_whenUserNameChanges() = runTest {
        val saltStore = RecordingSaltStore()
        val server = PrfTestServerClient()
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = saltStore,
        )

        controller.signInWithPrf(prfDemoConfig().copy(userName = "first@local"), supportsPrf = true)
        controller.signInWithPrf(prfDemoConfig().copy(userName = "second@local"), supportsPrf = true)

        assertEquals(
            listOf("example.test:demo-user-1", "example.test:demo-user-1"),
            saltStore.loadedKeys,
        )
    }

    @Test
    fun signInWithPrf_mapsStartTransportException_toFailure() = runTest {
        val server = PrfTestServerClient(startThrowable = IllegalStateException("start exploded"))
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val result = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)

        val failure = assertIs<PrfDemoResult.Failure>(result)
        assertTrue(failure.message.contains("PRF sign-in start failed"))
        assertTrue(failure.message.contains("start exploded"))
    }

    @Test
    fun signInWithPrf_mapsFinishTransportException_toFailure() = runTest {
        val server = PrfTestServerClient(finishThrowable = IllegalStateException("finish exploded"))
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val result = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)

        val failure = assertIs<PrfDemoResult.Failure>(result)
        assertTrue(failure.message.contains("PRF sign-in finish failed"))
        assertTrue(failure.message.contains("finish exploded"))
    }

    @Test
    fun signInWithPrf_rethrowsCancellation_fromStartCall() = runTest {
        val server = PrfTestServerClient(startThrowable = CancellationException("start cancelled"))
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        assertFailsWith<CancellationException> {
            controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        }
    }

    @Test
    fun signInWithPrf_rethrowsCancellation_fromFinishCall() = runTest {
        val server = PrfTestServerClient(finishThrowable = CancellationException("finish cancelled"))
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        assertFailsWith<CancellationException> {
            controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        }
    }

    @Test
    fun clearSession_isIdempotent_and_resetsFlags() = runTest {
        val server = PrfTestServerClient()
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val signInResult = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        assertIs<PrfDemoResult.Success>(signInResult)
        controller.encrypt("clear me")
        assertEquals(PrfCryptoDemoSessionState.CiphertextReady, controller.sessionState)

        val firstClear = controller.clearSession()
        assertIs<PrfDemoResult.Success>(firstClear)
        assertTrue(firstClear.message.contains("cleared"))
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)

        val secondClear = controller.clearSession()
        assertIs<PrfDemoResult.Success>(secondClear)
        assertTrue(secondClear.message.contains("No active PRF session."))
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun secondSignIn_replacesSession_and_dropsPriorCiphertext() = runTest {
        val server = PrfTestServerClient()
        val passkeyClient = PrfTestPasskeyClient(PasskeyResult.Success(validAuthenticationResponseWithPrf()))
        val controller = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = server,
            saltStore = FixedSaltStore(),
        )

        val firstSignIn = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        assertIs<PrfDemoResult.Success>(firstSignIn)
        val encryptResult = controller.encrypt("old payload")
        assertIs<PrfDemoResult.Success>(encryptResult)
        assertEquals(PrfCryptoDemoSessionState.CiphertextReady, controller.sessionState)

        val secondSignIn = controller.signInWithPrf(prfDemoConfig(), supportsPrf = true)
        assertIs<PrfDemoResult.Success>(secondSignIn)
        assertEquals(PrfCryptoDemoSessionState.SessionReady, controller.sessionState)

        val decryptAfterSecondSignIn = controller.decrypt()
        val failure = assertIs<PrfDemoResult.Failure>(decryptAfterSecondSignIn)
        assertTrue(failure.message.contains("No ciphertext. Encrypt text first."))
    }
}

private class FixedSaltStore : PrfSaltStore {
    val salt: Base64UrlBytes = Base64UrlBytes.fromBytes(ByteArray(32) { 3 })

    override fun loadOrCreate(key: String): Base64UrlBytes = salt
}

private class RecordingSaltStore : PrfSaltStore {
    private val salt: Base64UrlBytes = Base64UrlBytes.fromBytes(ByteArray(32) { 7 })
    val loadedKeys: MutableList<String> = mutableListOf()

    override fun loadOrCreate(key: String): Base64UrlBytes {
        loadedKeys += key
        return salt
    }
}

private class PrfTestServerClient(
    private val signInOptions: ValidationResult<PublicKeyCredentialRequestOptions> = ValidationResult.Valid(
        PublicKeyCredentialRequestOptions(
            challenge = Challenge.fromBytes(ByteArray(32) { 9 }),
            rpId = RpId.parseOrThrow("example.test"),
        ),
    ),
    private val signInVerifyResult: Boolean = true,
    private val startThrowable: Throwable? = null,
    private val finishThrowable: Throwable? = null,
) : AuthenticationBackend<AuthenticationStartPayload, Unit, PasskeyFinishResult> {
    var signInStartCalls: Int = 0
    var lastAuthenticationStartPayload: AuthenticationStartPayload? = null

    override suspend fun start(
        input: AuthenticationStartPayload,
    ): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> {
        startThrowable?.let { throw it }
        signInStartCalls += 1
        lastAuthenticationStartPayload = input
        val options = when (signInOptions) {
            is ValidationResult.Valid -> signInOptions.value
            is ValidationResult.Invalid -> error("authentication options are invalid")
        }
        return CeremonyStart(state = Unit, options = options)
    }

    override suspend fun finish(state: Unit, response: RawAuthenticationResponse): PasskeyFinishResult {
        finishThrowable?.let { throw it }
        return if (signInVerifyResult) {
            PasskeyFinishResult.Verified
        } else {
            PasskeyFinishResult.Rejected("invalid assertion")
        }
    }
}

private class PrfTestPasskeyClient(
    private val assertionResult: PasskeyResult<RawAuthenticationResponse>,
) : PasskeyClient {
    var lastAssertionOptions: PublicKeyCredentialRequestOptions? = null

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RawRegistrationResponse> {
        error("not used")
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<RawAuthenticationResponse> {
        lastAssertionOptions = options
        return assertionResult
    }
}

private fun validAuthenticationResponseWithPrf(): RawAuthenticationResponse {
    return RawAuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
        extensions = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(
                enabled = true,
                results = AuthenticationExtensionsPRFValues(
                    first = Base64UrlBytes.fromBytes(byteArrayOf(5, 4, 3, 2, 1)),
                ),
            ),
        ),
    )
}

private fun prfDemoConfig(): PasskeyDemoConfig {
    return PasskeyDemoConfig(
        endpointBase = "https://example.test",
        rpId = "example.test",
        origin = "https://example.test",
        userHandle = "demo-user-1",
        userName = "demo@local",
    )
}
