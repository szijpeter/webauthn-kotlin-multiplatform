@file:OptIn(dev.webauthn.model.ExperimentalWebAuthnL3Api::class)

package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RpId
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
        assertFalse(controller.hasSession)
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
        assertTrue(controller.hasSession)
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
        assertTrue(controller.hasEncryptedPayload)

        val decryptResult = controller.decrypt()
        assertIs<PrfDemoResult.Success>(decryptResult)
        assertEquals("hello prf", decryptResult.plaintext)

        controller.clearSession()
        assertFalse(controller.hasSession)
        assertFalse(controller.hasEncryptedPayload)
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
        assertFalse(controller.hasSession)
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
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    var signInStartCalls: Int = 0
    var lastAuthenticationStartPayload: AuthenticationStartPayload? = null

    override suspend fun getRegisterOptions(params: RegistrationStartPayload): ValidationResult<PublicKeyCredentialCreationOptions> {
        error("not used")
    }

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: dev.webauthn.model.RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        error("not used")
    }

    override suspend fun getSignInOptions(params: AuthenticationStartPayload): ValidationResult<PublicKeyCredentialRequestOptions> {
        startThrowable?.let { throw it }
        signInStartCalls += 1
        lastAuthenticationStartPayload = params
        return signInOptions
    }

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        finishThrowable?.let { throw it }
        return if (signInVerifyResult) {
            PasskeyFinishResult.Verified
        } else {
            PasskeyFinishResult.Rejected("invalid assertion")
        }
    }
}

private class PrfTestPasskeyClient(
    private val assertionResult: PasskeyResult<AuthenticationResponse>,
) : PasskeyClient {
    var lastAssertionOptions: PublicKeyCredentialRequestOptions? = null

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<dev.webauthn.model.RegistrationResponse> {
        error("not used")
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        lastAssertionOptions = options
        return assertionResult
    }
}

private fun validAuthenticationResponseWithPrf(): AuthenticationResponse {
    return AuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        rawAuthenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        authenticatorData = AuthenticatorData(
            rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 1 }),
            flags = 0x01,
            signCount = 2,
        ),
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
