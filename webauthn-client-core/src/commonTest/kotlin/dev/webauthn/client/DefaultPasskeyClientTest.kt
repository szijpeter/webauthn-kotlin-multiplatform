package dev.webauthn.client

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.RpId
import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.LargeBlobExtensionOutput
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialDescriptor
import dev.webauthn.model.UserHandle
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DefaultPasskeyClientTest {

    @Test
    fun createCredential_rejects_empty_pub_key_params() = runTest {
        val client = DefaultPasskeyClient(bridge = TestBridge())

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
            bridge = TestBridge(
                assertionAction = { error("boom") },
                errorMapper = { PasskeyClientError.Transport("mapped", it) },
            ),
        )

        val result = client.getAssertion(
            PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
                allowCredentials = listOf(
                    PublicKeyCredentialDescriptor(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        id = CredentialId.fromBytes(byteArrayOf(1)),
                    ),
                ),
            ),
        )

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.Transport)
        assertEquals("mapped", result.error.message)
    }

    @Test
    fun getAssertion_maps_platform_user_cancel_without_treating_it_as_coroutine_cancellation() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                assertionAction = { throw IllegalStateException("platform canceled prompt") },
                errorMapper = { PasskeyClientError.UserCancelled("cancelled by user prompt") },
            ),
        )

        val result = client.getAssertion(
            PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
                allowCredentials = listOf(
                    PublicKeyCredentialDescriptor(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        id = CredentialId.fromBytes(byteArrayOf(1)),
                    ),
                ),
            ),
        )

        val failure = assertIs<PasskeyResult.Failure>(result)
        assertIs<PasskeyClientError.UserCancelled>(failure.error)
        assertTrue(failure.error.message.contains("cancelled"))
    }

    @Test
    fun createCredential_maps_illegal_argument_to_invalid_options() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                createAction = { throw IllegalArgumentException("bad options") },
                errorMapper = { PasskeyClientError.Platform("unexpected", it) },
            ),
        )

        val result = client.createCredential(validCreationOptions())

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
        assertTrue(result.error.message.contains("bad options"))
    }

    @Test
    fun createCredential_uses_bridge_invalid_options_message_for_illegal_argument() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                createAction = { throw IllegalArgumentException("RP ID cannot be validated") },
                errorMapper = { PasskeyClientError.InvalidOptions("RP ID cannot be validated. hint") },
            ),
        )

        val result = client.createCredential(validCreationOptions())

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
        assertTrue(result.error.message.contains("hint"))
    }

    @Test
    fun capabilities_default_to_bridge_values() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                capabilitiesAction = {
                    PasskeyCapabilities(
                        supportsPrf = true,
                        platformVersionHints = listOf("test"),
                    )
                },
            ),
        )

        val capabilities = client.capabilities()
        assertTrue(capabilities.supportsPrf)
        assertEquals(listOf("test"), capabilities.platformVersionHints)
    }

    @Test
    fun createCredential_passes_extensions_to_bridge() = runTest {
        var passedExtensions: AuthenticationExtensionsClientInputs? = null
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                createAction = {
                    passedExtensions = it.extensions
                    validRegistrationResponse()
                },
            ),
        )

        val extensions = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(
                    first = base64UrlBytes(1, 2, 3),
                ),
            ),
        )
        val result = client.createCredential(validCreationOptions().copy(extensions = extensions))

        assertTrue(result is PasskeyResult.Success)
        assertNotNull(passedExtensions)
        assertNotNull(passedExtensions?.prf?.eval)
        assertContentEquals(byteArrayOf(1, 2, 3), passedExtensions?.prf?.eval?.first?.bytes())
    }

    @Test
    fun getAssertion_maps_extension_results_from_bridge() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                assertionAction = {
                    validAuthenticationResponse().copy(
                        extensions = AuthenticationExtensionsClientOutputs(
                            largeBlob = LargeBlobExtensionOutput(
                                supported = true,
                                blob = base64UrlBytes(4, 5, 6),
                            ),
                        ),
                    )
                },
            ),
        )

        val result = client.getAssertion(
            PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
                allowCredentials = listOf(
                    PublicKeyCredentialDescriptor(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        id = CredentialId.fromBytes(byteArrayOf(1)),
                    ),
                ),
            ),
        )

        assertTrue(result is PasskeyResult.Success)
        val extensions = result.value.extensions
        assertNotNull(extensions)
        assertNotNull(extensions.largeBlob)
        assertEquals(extensions.largeBlob?.supported, true)
        assertContentEquals(byteArrayOf(4, 5, 6), extensions.largeBlob?.blob?.bytes())
    }

    @Test
    fun createCredential_propagates_cancellation_exception() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                createAction = { throw CancellationException("cancelled") },
            ),
        )

        assertFailsWith<CancellationException> {
            client.createCredential(validCreationOptions())
        }
    }

    @Test
    fun getAssertion_propagates_cancellation_exception() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                assertionAction = { throw CancellationException("cancelled") },
            ),
        )

        assertFailsWith<CancellationException> {
            client.getAssertion(
                PublicKeyCredentialRequestOptions(
                    challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                    rpId = RpId.parseOrThrow("example.com"),
                    allowCredentials = listOf(
                        PublicKeyCredentialDescriptor(
                            type = PublicKeyCredentialType.PUBLIC_KEY,
                            id = CredentialId.fromBytes(byteArrayOf(1)),
                        ),
                    ),
                ),
            )
        }
    }

    @Test
    fun capabilities_propagates_cancellation_exception() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                capabilitiesAction = { throw CancellationException("cancelled") },
            ),
        )

        assertFailsWith<CancellationException> {
            client.capabilities()
        }
    }

    @Test
    fun capabilities_returns_default_on_non_cancellation_failure() = runTest {
        val client = DefaultPasskeyClient(
            bridge = TestBridge(
                capabilitiesAction = { throw IllegalStateException("boom") },
            ),
        )

        assertEquals(PasskeyCapabilities(), client.capabilities())
    }

    private class TestBridge(
        private val createAction: suspend (PublicKeyCredentialCreationOptions) -> RegistrationResponse = { validRegistrationResponse() },
        private val assertionAction: suspend (PublicKeyCredentialRequestOptions) -> AuthenticationResponse = { validAuthenticationResponse() },
        private val errorMapper: (Throwable) -> PasskeyClientError = { PasskeyClientError.Platform(it.message ?: "platform", it) },
        private val capabilitiesAction: suspend () -> PasskeyCapabilities = { PasskeyCapabilities() },
    ) : PasskeyPlatformBridge {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse = createAction(options)

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse = assertionAction(options)

        override fun mapPlatformError(throwable: Throwable): PasskeyClientError = errorMapper(throwable)

        override suspend fun capabilities(): PasskeyCapabilities = capabilitiesAction()
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
                    rpIdHash = rpIdHash(1),
                    flags = 0x41,
                    signCount = 1,
                ),
                attestedCredentialData = AttestedCredentialData(
                    aaguid = aaguid(2),
                    credentialId = CredentialId.fromBytes(byteArrayOf(9, 9, 9)),
                    cosePublicKey = CosePublicKey.fromBytes(byteArrayOf(1, 2, 3)),
                ),
            )
        }

        fun validAuthenticationResponse(): AuthenticationResponse {
            return AuthenticationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(8, 8, 8)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)),
                rawAuthenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 3 }),
                authenticatorData = AuthenticatorData(
                    rpIdHash = rpIdHash(4),
                    flags = 0x01,
                    signCount = 2,
                ),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(5, 5, 5)),
            )
        }

        fun rpIdHash(seed: Int): RpIdHash = RpIdHash.fromBytes(ByteArray(32) { seed.toByte() })

        fun aaguid(seed: Int): Aaguid = Aaguid.fromBytes(ByteArray(16) { seed.toByte() })

        fun base64UrlBytes(vararg value: Int): Base64UrlBytes =
            Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })
    }
}
