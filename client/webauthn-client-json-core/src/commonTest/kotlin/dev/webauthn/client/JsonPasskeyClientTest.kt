package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.protocol.WebAuthnProtocolParser
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonPasskeyClientTest {
    private val codec = KotlinxWebAuthnJsonCodec()

    @Test
    fun createCredentialJson_rejects_invalid_json() = runTest {
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(),
            codec = codec,
        )

        val result = jsonClient.createCredentialJson("{not-json")

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
    }

    @Test
    fun createCredentialJson_returns_normalized_response_json() = runTest {
        val registrationResponse = WebAuthnProtocolParser.parseRegistrationResponse(
            codec.decodeRegistrationResponse(
            """
            {
              "id": "MzMzMzMzMzMzMzMzMzMzMw",
              "rawId": "MzMzMzMzMzMzMzMzMzMzMw",
              "response": {
                "clientDataJSON": "BAUG",
                "attestationObject": "o2NmbXRkbm9uZWhhdXRoRGF0YVhKRERERERERERERERERERERERERERERERERERERERERERBAAAACVVVVVVVVVVVVVVVVVVVVVUAEDMzMzMzMzMzMzMzMzMzMzOhAQJnYXR0U3RtdKA"
              }
            }
                """.trimIndent(),
            ).toValueOrThrow(::IllegalStateException),
        ).toValueOrThrow(::IllegalStateException)
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(createResult = PasskeyResult.Success(registrationResponse)),
            codec = codec,
        )
        val requestJson = codec.encodeCreationOptions(validCreationOptions())

        val result = jsonClient.createCredentialJson(requestJson)

        assertTrue(result is PasskeyResult.Success)
        assertTrue(result.value.contains("\"type\":\"public-key\""))
        assertTrue(result.value.contains("\"clientExtensionResults\":{}"))
        val decoded = codec.decodeRegistrationResponse(result.value).toValueOrThrow(::IllegalStateException)
        assertEquals(registrationResponse.credentialId.value.encoded(), decoded.credentialId.value.encoded())
    }

    @Test
    fun getAssertionJson_propagates_typed_client_failure() = runTest {
        val failure = PasskeyResult.Failure(PasskeyClientError.UserCancelled())
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(assertionResult = failure),
            codec = codec,
        )
        val requestJson = codec.encodeRequestOptions(validRequestOptions())

        val result = jsonClient.getAssertionJson(requestJson)

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.UserCancelled)
    }

    @Test
    fun getAssertionJson_returns_normalized_response_json() = runTest {
        val authenticationResponse = WebAuthnProtocolParser.parseAuthenticationResponse(
            codec.decodeAuthenticationResponse(
            """
            {
              "id": "MzMzMzMzMzMzMzMzMzMzMw",
              "rawId": "MzMzMzMzMzMzMzMzMzMzMw",
              "response": {
                "clientDataJSON": "AQID",
                "authenticatorData": "REREREREREREREREREREREREREREREREREREREREREQFAAAAKg",
                "signature": "CQkJ"
              }
            }
                """.trimIndent(),
            ).toValueOrThrow(::IllegalStateException),
        ).toValueOrThrow(::IllegalStateException)
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(assertionResult = PasskeyResult.Success(authenticationResponse)),
            codec = codec,
        )
        val requestJson = codec.encodeRequestOptions(validRequestOptions())

        val result = jsonClient.getAssertionJson(requestJson)

        assertTrue(result is PasskeyResult.Success)
        assertTrue(result.value.contains("\"type\":\"public-key\""))
        assertTrue(result.value.contains("\"clientExtensionResults\":{}"))
        val decoded = codec.decodeAuthenticationResponse(result.value).toValueOrThrow(::IllegalStateException)
        assertEquals(authenticationResponse.credentialId.value.encoded(), decoded.credentialId.value.encoded())
    }

    @Test
    fun decodeAssertionOptionsOrThrowInvalid_acceptsNullAllowCredentials() {
        val payload = """
            {
              "challenge": "${validRequestOptions().challenge.value.encoded()}",
              "rpId": "example.com",
              "allowCredentials": null,
              "userVerification": "preferred"
            }
        """.trimIndent()

        val options = codec.decodeRequestOptions(payload).toValueOrThrow(::IllegalArgumentException)

        assertTrue(options.allowCredentials.isEmpty())
    }

    private class FakePasskeyClient(
        private val createResult: PasskeyResult<RegistrationResponse> =
            PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
        private val assertionResult: PasskeyResult<AuthenticationResponse> =
            PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
            return createResult
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
            return assertionResult
        }
    }

    private companion object {
        fun validCreationOptions(): PublicKeyCredentialCreationOptions {
            return PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
                pubKeyCredParams = [
                    PublicKeyCredentialParameters(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        alg = -7,
                    ),
                ],
            )
        }

        fun validRequestOptions(): PublicKeyCredentialRequestOptions {
            return PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
            )
        }
    }
}
