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
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DefaultPasskeyClientTest {
    @Test
    fun createCredential_rejects_empty_pub_key_params() = runTest {
        val client = DefaultPasskeyClient(
            bridge = StaticBridge(
                createResponse = validRegistrationResponse(),
                assertionResponse = validAuthenticationResponse(),
            ),
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
    fun getAssertion_maps_bridge_failures_with_platform_mapper() = runTest {
        val client = DefaultPasskeyClient(
            bridge = object : PasskeyPlatformBridge {
                override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
                    error("unused")
                }

                override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
                    throw IllegalStateException("boom")
                }

                override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
                    return PasskeyClientError.Transport("mapped", throwable)
                }
            },
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
    fun createCredential_maps_illegal_argument_to_invalid_options() = runTest {
        val client = DefaultPasskeyClient(
            bridge = object : PasskeyPlatformBridge {
                override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
                    throw IllegalArgumentException("bad options")
                }

                override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
                    return validAuthenticationResponse()
                }

                override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
                    return PasskeyClientError.Platform("unexpected", throwable)
                }
            },
        )

        val result = client.createCredential(validCreationOptions())

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
        assertTrue(result.error.message.contains("bad options"))
    }

    @Test
    fun capabilities_default_to_bridge_values() = runTest {
        val client = DefaultPasskeyClient(
            bridge = StaticBridge(
                createResponse = validRegistrationResponse(),
                assertionResponse = validAuthenticationResponse(),
                capabilities = PasskeyCapabilities(
                    supportsPrf = true,
                    platformVersionHints = listOf("test"),
                ),
            ),
        )

        val capabilities = client.capabilities()
        assertTrue(capabilities.supportsPrf)
        assertEquals(listOf("test"), capabilities.platformVersionHints)
    }

    @Test
    fun createCredential_passes_extensions_to_bridge() = runTest {
        var passedExtensions: dev.webauthn.model.AuthenticationExtensionsClientInputs? = null
        val client = DefaultPasskeyClient(
            bridge = object : PasskeyPlatformBridge {
                override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
                    passedExtensions = options.extensions
                    return validRegistrationResponse()
                }

                override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
                    error("unused")
                }

                override fun mapPlatformError(throwable: Throwable): PasskeyClientError = PasskeyClientError.Platform("err", throwable)
            },
        )

        val extensions = dev.webauthn.model.AuthenticationExtensionsClientInputs(
            prf = dev.webauthn.model.PrfExtensionInput(
                eval = dev.webauthn.model.AuthenticationExtensionsPRFValues(
                    first = byteArrayOf(1, 2, 3)
                )
            )
        )
        val result = client.createCredential(validCreationOptions().copy(extensions = extensions))

        assertTrue(result is PasskeyResult.Success)
        kotlin.test.assertNotNull(passedExtensions)
        kotlin.test.assertNotNull(passedExtensions?.prf?.eval)
        kotlin.test.assertContentEquals(byteArrayOf(1, 2, 3), passedExtensions?.prf?.eval?.first)
    }

    @Test
    fun getAssertion_maps_extension_results_from_bridge() = runTest {
        val client = DefaultPasskeyClient(
            bridge = object : PasskeyPlatformBridge {
                override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
                    error("unused")
                }

                override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
                    return validAuthenticationResponse().copy(
                        extensions = dev.webauthn.model.AuthenticationExtensionsClientOutputs(
                            largeBlob = dev.webauthn.model.LargeBlobExtensionOutput(
                                supported = true,
                                blob = byteArrayOf(4, 5, 6),
                            )
                        )
                    )
                }

                override fun mapPlatformError(throwable: Throwable): PasskeyClientError = PasskeyClientError.Platform("err", throwable)
            },
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

        assertTrue(result is PasskeyResult.Success)
        val extensions = result.value.extensions
        kotlin.test.assertNotNull(extensions)
        kotlin.test.assertNotNull(extensions.largeBlob)
        kotlin.test.assertTrue(extensions.largeBlob?.supported == true)
        kotlin.test.assertContentEquals(byteArrayOf(4, 5, 6), extensions.largeBlob?.blob)
    }

    private class StaticBridge(
        private val createResponse: RegistrationResponse,
        private val assertionResponse: AuthenticationResponse,
        private val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    ) : PasskeyPlatformBridge {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse = createResponse

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse = assertionResponse

        override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
            return PasskeyClientError.Platform(throwable.message ?: "platform", throwable)
        }

        override suspend fun capabilities(): PasskeyCapabilities = capabilities
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
