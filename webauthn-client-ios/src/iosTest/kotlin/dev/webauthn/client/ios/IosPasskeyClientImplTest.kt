package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import platform.AuthenticationServices.ASAuthorizationErrorCanceled
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.Foundation.NSError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class IosPasskeyClientImplTest {

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
        val delegate = IosPasskeyClientImpl(bridge)

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
                    userHandle = null,
                )
            )
        )
        val delegate = IosPasskeyClientImpl(bridge)

        val result = delegate.getAssertion(mockRequestOptions())
        assertTrue(result is PasskeyResult.Success)
        assertEquals("MzMzMzMzMzMzMzMzMzMzMw", result.value.credentialId.value.encoded())
    }

    @Test
    fun getAssertion_maps_prf_extension_results() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            getResult = Result.success(
                IosAuthenticationPayload(
                    credentialId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    rawId = decode("MzMzMzMzMzMzMzMzMzMzMw"),
                    clientDataJson = decode("AQID"),
                    authenticatorData = decode("REREREREREREREREREREREREREREREREREREREREREQFAAAAKg"),
                    signature = decode("CQkJ"),
                    userHandle = null,
                    extensions = AuthenticationExtensionsClientOutputs(
                        prf = PrfExtensionOutput(
                            enabled = true,
                            results = AuthenticationExtensionsPRFValues(
                                first = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                            ),
                        ),
                    ),
                ),
            ),
        )
        val delegate = IosPasskeyClientImpl(bridge)

        val result = delegate.getAssertion(mockRequestOptions())
        assertTrue(result is PasskeyResult.Success)
        val prfResults = result.value.extensions?.prf?.results
        assertEquals("AQID", prfResults?.first?.encoded())
    }

    @Test
    fun getAssertion_returns_InvalidOptions_on_unsupported_prf() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            getResult = Result.failure(
                IllegalArgumentException("PRF extension requires iOS 18+ with AuthenticationServices PRF APIs."),
            ),
        )
        val delegate = IosPasskeyClientImpl(bridge)

        val result = delegate.getAssertion(mockRequestOptions())
        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
        assertTrue(result.error.message.contains("PRF extension requires iOS 18+"))
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
        val delegate = IosPasskeyClientImpl(bridge)

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
                    userHandle = null,
                )
            )
        )
        val delegate = IosPasskeyClientImpl(bridge)

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
        val delegate = IosPasskeyClientImpl(bridge)

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
        val delegate = IosPasskeyClientImpl(bridge)

        val result = delegate.createCredential(mockOptions())
        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.UserCancelled)
    }

    @Test
    fun getAssertion_returns_InvalidOptions_when_rp_id_is_missing() = runBlocking {
        val bridge = object : IosAuthorizationBridge {
            override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): IosRegistrationPayload {
                throw IllegalStateException("unused")
            }

            override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): IosAuthenticationPayload {
                requireNotNull(options.rpId) {
                    "PublicKeyCredentialRequestOptions.rpId is required by the iOS AuthenticationServices bridge."
                }
                throw IllegalStateException("unused")
            }
        }
        val delegate = IosPasskeyClientImpl(bridge)

        val result = delegate.getAssertion(
            mockRequestOptions().copy(rpId = null),
        )

        assertTrue(result is PasskeyResult.Failure, "Expected failure but was $result")
        assertTrue(result.error is PasskeyClientError.InvalidOptions, "Expected InvalidOptions but was ${result.error}")
    }

    @Test
    fun getAssertion_propagates_coroutine_cancellation() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            getResult = Result.failure(CancellationException("cancelled")),
        )
        val delegate = IosPasskeyClientImpl(bridge)

        val error = assertFailsWith<CancellationException> {
            delegate.getAssertion(mockRequestOptions())
        }
        assertTrue(error.message?.contains("cancelled") == true)
    }

    @Test
    fun createCredential_propagates_coroutine_cancellation() = runBlocking {
        val bridge = FakeAuthorizationBridge(
            createResult = Result.failure(CancellationException("cancelled")),
        )
        val delegate = IosPasskeyClientImpl(bridge)

        val error = assertFailsWith<CancellationException> {
            delegate.createCredential(mockOptions())
        }
        assertTrue(error.message?.contains("cancelled") == true)
    }
}
