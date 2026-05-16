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
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonPasskeyClientTest {
    private val mapper = KotlinxPasskeyJsonMapper()

    @Test
    fun createCredentialJson_rejects_invalid_json() = runTest {
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(),
            jsonMapper = mapper,
        )

        val result = jsonClient.createCredentialJson("{not-json")

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.InvalidOptions)
        assertTrue(result.error.message.contains("Failed to parse registration options JSON"))
    }

    @Test
    fun createCredentialJson_returns_normalized_response_json() = runTest {
        val registrationResponse = mapper.decodeRegistrationResponseOrThrowPlatform(
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
        )
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(createResult = PasskeyResult.Success(registrationResponse)),
            jsonMapper = mapper,
        )
        val requestJson = mapper.encodeCreationOptionsOrThrowInvalid(validCreationOptions())

        val result = jsonClient.createCredentialJson(requestJson)

        assertTrue(result is PasskeyResult.Success)
        assertTrue(result.value.contains("\"type\":\"public-key\""))
        assertTrue(result.value.contains("\"clientExtensionResults\":{}"))
        val decoded = mapper.decodeRegistrationResponseOrThrowPlatform(result.value)
        assertEquals(registrationResponse.credentialId.value.encoded(), decoded.credentialId.value.encoded())
    }

    @Test
    fun getAssertionJson_propagates_typed_client_failure() = runTest {
        val failure = PasskeyResult.Failure(PasskeyClientError.UserCancelled())
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(assertionResult = failure),
            jsonMapper = mapper,
        )
        val requestJson = mapper.encodeAssertionOptionsOrThrowInvalid(validRequestOptions())

        val result = jsonClient.getAssertionJson(requestJson)

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error is PasskeyClientError.UserCancelled)
    }

    @Test
    fun getAssertionJson_returns_normalized_response_json() = runTest {
        val authenticationResponse = mapper.decodeAuthenticationResponseOrThrowPlatform(
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
        )
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = FakePasskeyClient(assertionResult = PasskeyResult.Success(authenticationResponse)),
            jsonMapper = mapper,
        )
        val requestJson = mapper.encodeAssertionOptionsOrThrowInvalid(validRequestOptions())

        val result = jsonClient.getAssertionJson(requestJson)

        assertTrue(result is PasskeyResult.Success)
        assertTrue(result.value.contains("\"type\":\"public-key\""))
        assertTrue(result.value.contains("\"clientExtensionResults\":{}"))
        val decoded = mapper.decodeAuthenticationResponseOrThrowPlatform(result.value)
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

        val options = mapper.decodeAssertionOptionsOrThrowInvalid(payload)

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
                pubKeyCredParams = listOf(
                    PublicKeyCredentialParameters(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        alg = -7,
                    ),
                ),
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
