package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import kotlinx.coroutines.runBlocking
import platform.AuthenticationServices.ASAuthorizationErrorCanceled
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.Foundation.NSError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IosPasskeyDelegateTest {

    private class FakeAuthorizationBridge(
        var createResult: Result<IosRegistrationPayload>? = null,
        var getResult: Result<IosAuthenticationPayload>? = null,
    ) : IosAuthorizationBridge {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): IosRegistrationPayload {
            return createResult?.getOrThrow() ?: throw IllegalStateException("Not configured")
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): IosAuthenticationPayload {
            return getResult?.getOrThrow() ?: throw IllegalStateException("Not configured")
        }
    }

    private fun mockOptions() = PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "name"),
        user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "name", "display"),
        challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
        pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7))
    )

    private fun mockRequestOptions() = PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
        rpId = RpId.parseOrThrow("example.com"),
    )

    private fun decode(base64url: String): ByteArray {
        val result = Base64UrlBytes.parse(base64url, "test")
        return (result as ValidationResult.Valid).value.bytes()
    }

    @Test
    fun createCredential_returns_Success_on_valid_payload() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            createResult = Result.success(
                IosRegistrationPayload(
                    credentialId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    rawId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    clientDataJson = decode("BAUG"),
                    attestationObject = decode("o2NmbXRkbm9uZWhhdXRoRGF0YVhKRERERERERERERERERERERERERERERERERERERERERERBAAAACVVVVVVVVVVVVVVVVVVVVVUAEDMzMzMzMzMzMzMzMzMzMzOhAQJnYXR0U3RtdKA")
                )
            )
        )
        val delegate = IosPasskeyDelegate(bridge)

        val result = delegate.createCredential(mockOptions())
        assertTrue(result is PasskeyResult.Success)
        assertEquals("MzMzMzMzMzMzMzMzMzMzMw", result.value.credentialId.value.encoded())
    }

    @Test
    fun getAssertion_returns_Success_on_valid_payload() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            getResult = Result.success(
                IosAuthenticationPayload(
                    credentialId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    rawId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    clientDataJson = decode("AQID"),
                    authenticatorData = decode("REREREREREREREREREREREREREREREREREREREREREQFAAAAKg"),
                    signature = decode("CQkJ"),
                    userHandle = null
                )
            )
        )
        val delegate = IosPasskeyDelegate(bridge)

        val result = delegate.getAssertion(mockRequestOptions())
        assertTrue(result is PasskeyResult.Success)
        assertEquals("MzMzMzMzMzMzMzMzMzMzMw", result.value.credentialId.value.encoded())
    }

    @Test
    fun createCredential_returns_Platform_error_on_malformed_payload() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            createResult = Result.success(
                IosRegistrationPayload(
                    credentialId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    rawId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    clientDataJson = decode("BAUG"),
                    attestationObject = ByteArray(10) // Invalid attestation
                )
            )
        )
        val delegate = IosPasskeyDelegate(bridge)

        val result = delegate.createCredential(mockOptions())
        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.Platform)
        assertTrue(result.error.message.contains("attestationObject"))
    }

    @Test
    fun getAssertion_returns_Platform_error_on_malformed_payload() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            getResult = Result.success(
                IosAuthenticationPayload(
                    credentialId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    rawId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    clientDataJson = decode("AQID"),
                    authenticatorData = ByteArray(10), // Invalid auth data (< 37)
                    signature = decode("CQkJ"),
                    userHandle = null
                )
            )
        )
        val delegate = IosPasskeyDelegate(bridge)

        val result = delegate.getAssertion(mockRequestOptions())
        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.Platform)
        assertTrue(result.error.message.contains("authenticatorData"))
    }

    @Test
    fun getAssertion_returns_UserCancelled_on_nserror_cancellation() = runBlocking {
        val error = NSError.errorWithDomain(ASAuthorizationErrorDomain, ASAuthorizationErrorCanceled, null)
        val bridge = FakeAuthorizationBridge(
            getResult = Result.failure(NSErrorException(error))
        )
        val delegate = IosPasskeyDelegate(bridge)

        val result = delegate.getAssertion(mockRequestOptions())
        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.UserCancelled)
    }

    @Test
    fun createCredential_returns_UserCancelled_on_nserror_cancellation() = runBlocking {
        val error = NSError.errorWithDomain(ASAuthorizationErrorDomain, ASAuthorizationErrorCanceled, null)
        val bridge = FakeAuthorizationBridge(
            createResult = Result.failure(NSErrorException(error))
        )
        val delegate = IosPasskeyDelegate(bridge)

        val result = delegate.createCredential(mockOptions())
        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.UserCancelled)
    }
}
