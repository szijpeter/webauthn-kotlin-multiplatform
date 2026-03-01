package dev.webauthn.network

import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class WebAuthnInteropKtorClientTest {
    @Test
    fun pocStartRegistration_mapsAuthenticatorAttachment() = runTest {
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/register/options" -> respond(
                    content =
                        """
                        {
                          "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                          "rp": {"id": "example.com", "name": "Example"},
                          "user": {"id": "AQID", "name": "alice", "displayName": "Alice"},
                          "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                          "authenticatorSelection": {
                            "authenticatorAttachment": "platform",
                            "residentKey": "required",
                            "userVerification": "required"
                          }
                        }
                        """.trimIndent(),
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val client = HttpClient(engine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val interop = WebAuthnInteropKtorClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )

        val result = interop.startRegistration(
            RegistrationStartPayload(
                rpId = "example.com",
                rpName = "Example",
                origin = "https://example.com",
                userName = "alice",
                userDisplayName = "Alice",
                userHandle = "AQID",
            ),
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals(AuthenticatorAttachment.PLATFORM, result.value.authenticatorAttachment)
        assertEquals("alice", result.value.user.name)
    }

    @Test
    fun pocFinishRegistration_reusesUserHandleFromChallenge() = runTest {
        val seenUrls = mutableListOf<String>()
        val engine = MockEngine { request ->
            seenUrls += request.url.toString()
            when (request.url.encodedPath) {
                "/register/options" -> respond(
                    content =
                        """
                        {
                          "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                          "rp": {"id": "example.com", "name": "Example"},
                          "user": {"id": "AQID", "name": "alice", "displayName": "Alice"},
                          "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
                        }
                        """.trimIndent(),
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                "/register/verify" -> respond(
                    content = """{"success":true}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val client = HttpClient(engine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val interop = WebAuthnInteropKtorClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )

        val start = interop.startRegistration(
            RegistrationStartPayload(
                rpId = "example.com",
                rpName = "Example",
                origin = "https://example.com",
                userName = "alice",
                userDisplayName = "Alice",
                userHandle = "AQID",
            ),
        )
        assertTrue(start is ValidationResult.Valid)

        val finishResult = interop.finishRegistration(
            RegistrationFinishPayload(
                response = RegistrationResponseDto(
                    id = "MzMzMzMzMzMzMzMzMzMzMw",
                    rawId = "MzMzMzMzMzMzMzMzMzMzMw",
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = "AQID",
                        attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oA",
                    ),
                ),
                clientDataType = "webauthn.create",
                challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                origin = "https://example.com",
            ),
        )

        assertTrue(finishResult)
        val verifyUrl = seenUrls.find { it.contains("/register/verify") }
        assertNotNull(verifyUrl)
        assertTrue(verifyUrl.contains("userId=AQID"))
    }

    @Test
    fun collectedClientDataHelpers_stillPopulateFinishPayloads() {
        val clientData = CollectedClientData(
            type = "webauthn.get",
            challenge = Challenge.fromBytes(ByteArray(16) { 2 }),
            origin = Origin.parseOrThrow("https://example.com"),
        )

        val payload = clientData.toAuthenticationFinishPayload(
            response = dev.webauthn.serialization.AuthenticationResponseDto(
                id = "YWFhYWFhYWFhYWFhYWFhYQ",
                rawId = "YWFhYWFhYWFhYWFhYWFhYQ",
                response = dev.webauthn.serialization.AuthenticationResponsePayloadDto(
                    clientDataJson = "AQID",
                    authenticatorData = "REREREREREREREREREREREREREREREREREREREREREQFAAAAKg",
                    signature = "CQkJ",
                ),
            ),
        )

        assertEquals("webauthn.get", payload.clientDataType)
        assertEquals("https://example.com", payload.origin)
    }
}
