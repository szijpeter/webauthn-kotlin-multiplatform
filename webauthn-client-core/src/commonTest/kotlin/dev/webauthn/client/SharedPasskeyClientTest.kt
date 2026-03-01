package dev.webauthn.client

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SharedPasskeyClientTest {
    @Test
    fun createCredential_rejects_empty_pub_key_params() = runTest {
        val client = SharedPasskeyClient(
            bridge = StaticBridge(createResponse = "{}", assertionResponse = "{}"),
            jsonCodec = FakeJsonCodec(),
        )

        val result = client.createCredential(
            PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
                pubKeyCredParams = emptyList(),
            ),
        )

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
    }

    @Test
    fun createCredentialJson_rejects_invalid_json() = runTest {
        val client = SharedPasskeyClient(
            bridge = StaticBridge(createResponse = "{}", assertionResponse = "{}"),
            jsonCodec = FakeJsonCodec(),
        )

        val result = client.createCredentialJson("{not-json")

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
        assertTrue(result.error.message.contains("Failed to parse registration options JSON"))
    }

    @Test
    fun createCredentialJson_returns_normalized_response_json() = runTest {
        val client = SharedPasskeyClient(
            bridge = StaticBridge(
                createResponse = FakeJsonCodec.BRIDGE_CREATE_RESPONSE,
                assertionResponse = "{}",
            ),
            jsonCodec = FakeJsonCodec(),
        )

        val result = client.createCredentialJson(FakeJsonCodec.VALID_CREATE_REQUEST_JSON)

        assertTrue(result is PasskeyResult.Success)
        assertEquals(FakeJsonCodec.NORMALIZED_CREATE_RESPONSE_JSON, result.value)
    }

    @Test
    fun getAssertion_maps_bridge_failures_with_platform_mapper() = runTest {
        val client = SharedPasskeyClient(
            bridge = object : PasskeyPlatformBridge {
                override suspend fun createCredential(requestJson: String): String = error("unused")

                override suspend fun getAssertion(requestJson: String): String {
                    throw IllegalStateException("boom")
                }

                override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
                    return PasskeyClientError.Transport("mapped", throwable)
                }
            },
            jsonCodec = FakeJsonCodec(),
        )

        val result = client.getAssertion(
            PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
                allowCredentials = listOf(
                    dev.webauthn.model.PublicKeyCredentialDescriptor(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        id = dev.webauthn.model.CredentialId.fromBytes(byteArrayOf(1)),
                    ),
                ),
            ),
        )

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.Transport)
        assertEquals("mapped", result.error.message)
    }

    @Test
    fun capabilities_default_to_bridge_values() = runTest {
        val client = SharedPasskeyClient(
            bridge = StaticBridge(
                createResponse = "{}",
                assertionResponse = "{}",
                capabilities = PasskeyCapabilities(
                    supportsPrf = true,
                    platformVersionHints = listOf("test"),
                ),
            ),
            jsonCodec = FakeJsonCodec(),
        )

        val capabilities = client.capabilities()
        assertTrue(capabilities.supportsPrf)
        assertEquals(listOf("test"), capabilities.platformVersionHints)
    }

    private class StaticBridge(
        private val createResponse: String,
        private val assertionResponse: String,
        private val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    ) : PasskeyPlatformBridge {
        override suspend fun createCredential(requestJson: String): String = createResponse

        override suspend fun getAssertion(requestJson: String): String = assertionResponse

        override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
            return PasskeyClientError.Platform(throwable.message ?: "platform", throwable)
        }

        override suspend fun capabilities(): PasskeyCapabilities = capabilities
    }

    private class FakeJsonCodec : PasskeyJsonCodec {
        override fun encodeCreationOptions(options: PublicKeyCredentialCreationOptions): String = "encoded-create-options"

        override fun decodeCreationOptions(payload: String): ValidationResult<PublicKeyCredentialCreationOptions> {
            return when (payload) {
                VALID_CREATE_REQUEST_JSON -> ValidationResult.Valid(validCreationOptions())
                else -> throw IllegalArgumentException("Malformed JSON")
            }
        }

        override fun encodeAssertionOptions(options: PublicKeyCredentialRequestOptions): String = "encoded-assertion-options"

        override fun decodeAssertionOptions(payload: String): ValidationResult<PublicKeyCredentialRequestOptions> {
            return ValidationResult.Valid(
                PublicKeyCredentialRequestOptions(
                    challenge = Challenge.fromBytes(ByteArray(32) { 3 }),
                    rpId = RpId.parseOrThrow("example.com"),
                ),
            )
        }

        override fun encodeRegistrationResponse(response: RegistrationResponse): String {
            return NORMALIZED_CREATE_RESPONSE_JSON
        }

        override fun decodeRegistrationResponse(payload: String): ValidationResult<RegistrationResponse> {
            return when (payload) {
                BRIDGE_CREATE_RESPONSE -> ValidationResult.Valid(validRegistrationResponse())
                else -> ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidFormat(
                            field = "registrationResponse",
                            message = "unexpected payload",
                        ),
                    ),
                )
            }
        }

        override fun encodeAuthenticationResponse(response: AuthenticationResponse): String = "normalized-auth-response"

        override fun decodeAuthenticationResponse(payload: String): ValidationResult<AuthenticationResponse> {
            return ValidationResult.Valid(validAuthenticationResponse())
        }

        companion object {
            const val VALID_CREATE_REQUEST_JSON = "valid-create-request-json"
            const val BRIDGE_CREATE_RESPONSE = "bridge-create-response"
            const val NORMALIZED_CREATE_RESPONSE_JSON = "{\"id\":\"normalized-credential-id\"}"
        }
    }

    private companion object {
        fun validCreationOptions(): PublicKeyCredentialCreationOptions {
            return PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
                pubKeyCredParams = listOf(
                    PublicKeyCredentialParameters(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        alg = -7,
                    ),
                ),
            )
        }

        fun validRegistrationResponse(): RegistrationResponse {
            return RegistrationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
                rawAuthenticatorData = AuthenticatorData(
                    rpIdHash = ByteArray(32) { 1 },
                    flags = 0x41,
                    signCount = 1,
                ),
                attestedCredentialData = AttestedCredentialData(
                    aaguid = ByteArray(16) { 2 },
                    credentialId = CredentialId.fromBytes(byteArrayOf(9, 9, 9)),
                    cosePublicKey = byteArrayOf(1, 2, 3),
                ),
            )
        }

        fun validAuthenticationResponse(): AuthenticationResponse {
            return AuthenticationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(8, 8, 8)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)),
                rawAuthenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 3 }),
                authenticatorData = AuthenticatorData(
                    rpIdHash = ByteArray(32) { 4 },
                    flags = 0x01,
                    signCount = 2,
                ),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(5, 5, 5)),
            )
        }
    }
}
