@file:OptIn(dev.webauthn.model.ExperimentalWebAuthnL3Api::class)

package dev.webauthn.client.swift

import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.PlatformCapability
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SwiftPasskeyBridgeTest {
    @Test
    fun passkeyResultFactories_enforceSuccessAndFailureShapes() {
        val success = success("{\"ok\":true}")
        val failure = failure("platform", "Platform failed")

        assertTrue(success.isSuccess)
        assertNull(success.errorCode)
        assertFalse(failure.isSuccess)
        assertNull(failure.responseJson)
    }

    @Test
    fun errorMapping_isExhaustiveAndStable() {
        val mappings = [
            PasskeyClientError.UserCancelled() to "userCancelled",
            PasskeyClientError.NoCredential() to "noCredential",
            PasskeyClientError.InvalidOptions("invalid") to "invalidOptions",
            PasskeyClientError.Platform("platform") to "platform",
            PasskeyClientError.Codec("codec") to "codec",
        ]

        mappings.forEach { (error, expectedCode) ->
            assertEquals(expectedCode, error.toSwiftBridgeFailure().code)
        }
    }

    @Test
    fun capabilities_preserveKnownAndCustomIdentifiers() {
        val capabilities = PasskeyCapabilities(
            mapOf(
                PasskeyCapability.Extension(WebAuthnExtension.Prf) to CapabilitySupport.SUPPORTED,
                PasskeyCapability.Extension(WebAuthnExtension.LargeBlob) to CapabilitySupport.UNSUPPORTED,
                PasskeyCapability.Platform(PlatformCapability.SecurityKey) to CapabilitySupport.UNKNOWN,
                PasskeyCapability.Platform(PlatformCapability.Custom("hybridTransport")) to
                    CapabilitySupport.SUPPORTED,
            ),
        ).toSwiftBridgeCapabilities()

        assertEquals(4, capabilities.reportedCount)
        assertEquals(
            "[{\"kind\":\"extension\",\"id\":\"largeBlob\",\"support\":\"unsupported\"}," +
                "{\"kind\":\"extension\",\"id\":\"prf\",\"support\":\"supported\"}," +
                "{\"kind\":\"platform\",\"id\":\"hybridTransport\",\"support\":\"supported\"}," +
                "{\"kind\":\"platform\",\"id\":\"securityKey\",\"support\":\"unknown\"}]",
            capabilities.valuesJson,
        )
    }

    @Test
    fun capabilities_preserveCollidingExtensionAndPlatformIdentifiers() {
        val capabilities = PasskeyCapabilities(
            mapOf(
                PasskeyCapability.Extension(WebAuthnExtension.Custom("securityKey")) to
                    CapabilitySupport.SUPPORTED,
                PasskeyCapability.Platform(PlatformCapability.SecurityKey) to
                    CapabilitySupport.UNKNOWN,
            ),
        ).toSwiftBridgeCapabilities()

        assertEquals(2, capabilities.reportedCount)
        assertEquals(
            "[{\"kind\":\"extension\",\"id\":\"securityKey\",\"support\":\"supported\"}," +
                "{\"kind\":\"platform\",\"id\":\"securityKey\",\"support\":\"unknown\"}]",
            capabilities.valuesJson,
        )
    }

    @Test
    fun ceremonies_preserveSuccessAndTypedFailure() = runTest {
        val jsonClient = FakeJsonPasskeyClient(
            create = PasskeyResult.Success("{\"registration\":true}"),
            get = PasskeyResult.Failure(PasskeyClientError.UserCancelled()),
        )
        val bridge = SwiftPasskeyBridge(FakePasskeyClient(), jsonClient)

        val registration = bridge.createCredential("{}")
        val authentication = bridge.getAssertion("{}")

        assertEquals("{\"registration\":true}", registration.responseJson)
        assertEquals("userCancelled", authentication.errorCode)
    }

    @Test
    fun ceremonies_distinguishConcurrencyFromInternalStateFailures() = runTest {
        val failingJsonClient = FakeJsonPasskeyClient(
            create = PasskeyResult.Success("{}"),
            get = PasskeyResult.Success("{}"),
            createFailure = IllegalStateException("unrelated internal state"),
        )
        val failingBridge = SwiftPasskeyBridge(FakePasskeyClient(), failingJsonClient)
        val internalFailure = failingBridge.createCredential("{}")

        val nestedBridge = SwiftPasskeyBridge(
            FakePasskeyClient(),
            FakeJsonPasskeyClient(
                create = PasskeyResult.Success("{}"),
                get = PasskeyResult.Success("{}"),
            ),
        )
        val concurrentFailure = nestedBridge.runExclusive {
            nestedBridge.createCredential("{}")
        }

        assertEquals("bridgeContract", internalFailure.errorCode)
        assertEquals("operationInProgress", concurrentFailure.errorCode)
    }

    @Test
    fun ceremonies_neverMapCancellationToADomainFailure() = runTest {
        val jsonClient = FakeJsonPasskeyClient(
            create = PasskeyResult.Success("{}"),
            get = PasskeyResult.Success("{}"),
            createFailure = CancellationException("cancelled"),
        )
        val bridge = SwiftPasskeyBridge(FakePasskeyClient(), jsonClient)

        assertFailsWith<CancellationException> {
            bridge.createCredential("{}")
        }
    }

    @Test
    fun prfBridge_authenticatesAndReturnsRawOutputs() = runTest {
        val codec = KotlinxWebAuthnJsonCodec()
        val prfOutput = Base64UrlBytes.fromBytes(ByteArray(32) { 9 })
        val passkeyClient = FakePasskeyClient(
            assertion = PasskeyResult.Success(validAuthenticationResponse(prfOutput)),
        )
        val bridge = SwiftPrfBridge(passkeyClient, codec)

        val authentication = bridge.authenticate(
            requestJson = codec.encodeRequestOptions(validRequestOptions()),
            firstSaltBase64Url = Base64UrlBytes.fromBytes(ByteArray(32) { 1 }).encoded(),
            secondSaltBase64Url = null,
        )

        assertTrue(authentication.isSuccess)
        assertEquals(prfOutput.encoded(), authentication.firstResultBase64Url)
        assertEquals(
            Base64UrlBytes.fromBytes(ByteArray(32) { 1 }),
            assertNotNull(passkeyClient.lastAssertionOptions).extensions?.prf?.eval?.first,
        )
    }

    @Test
    fun prfBridge_rejectsMalformedInputWithoutPrompting() = runTest {
        val passkeyClient = FakePasskeyClient()
        val bridge = SwiftPrfBridge(passkeyClient)

        val result = bridge.authenticate(
            requestJson = "{not-json",
            firstSaltBase64Url = "invalid=",
            secondSaltBase64Url = null,
        )

        assertEquals("invalidOptions", result.errorCode)
        assertEquals(0, passkeyClient.assertionCalls)
    }

    private class FakeJsonPasskeyClient(
        private val create: PasskeyResult<String>,
        private val get: PasskeyResult<String>,
        private val createFailure: Throwable? = null,
    ) : JsonPasskeyClient {
        override suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
            createFailure?.let { throw it }
            return create
        }

        override suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> = get
    }

    private class FakePasskeyClient(
        private val assertion: PasskeyResult<RawAuthenticationResponse> =
            PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    ) : PasskeyClient {
        var assertionCalls: Int = 0
        var lastAssertionOptions: PublicKeyCredentialRequestOptions? = null

        override suspend fun createCredential(
            options: PublicKeyCredentialCreationOptions,
        ): PasskeyResult<RawRegistrationResponse> =
            PasskeyResult.Failure(PasskeyClientError.Platform("unused"))

        override suspend fun getAssertion(
            options: PublicKeyCredentialRequestOptions,
        ): PasskeyResult<RawAuthenticationResponse> {
            assertionCalls += 1
            lastAssertionOptions = options
            return assertion
        }

        override suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
    }

    private companion object {
        fun validRequestOptions(): PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions(
            challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
            rpId = RpId.parseOrThrow("example.com"),
        )

        fun validAuthenticationResponse(prfOutput: Base64UrlBytes): RawAuthenticationResponse =
            RawAuthenticationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(8, 8, 8)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)),
                authenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 3 }),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(5, 5, 5)),
                extensions = AuthenticationExtensionsClientOutputs(
                    prf = PrfExtensionOutput(
                        results = AuthenticationExtensionsPRFValues(first = prfOutput),
                    ),
                ),
            )
    }
}
