package dev.webauthn.network

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.core.readText
import io.ktor.utils.io.readRemaining
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class KtorPasskeyServerClientTest {
    @Test
    fun libraryRoutes_registration_usesExpectedEndpointsAndPayloadShape() = runTest {
        val requestBodies = mutableMapOf<String, String>()
        val client = createMockClient { request ->
            when (request.url.encodedPath) {
                "/webauthn/registration/start" -> {
                    requestBodies[request.url.encodedPath] = request.bodyText()
                    respond(
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
                }

                "/webauthn/registration/finish" -> {
                    requestBodies[request.url.encodedPath] = request.bodyText()
                    respond(
                        content = """{"status":"ok"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )
                }

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.LIBRARY_ROUTES,
        )
        val params = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )

        val start = serverClient.getRegisterOptions(params)
        assertTrue(start is ValidationResult.Valid)

        val finished = serverClient.finishRegister(
            params = params,
            response = validRegistrationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assertTrue(finished)

        val startBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/registration/start")).jsonObject
        assertEquals("example.com", startBody["rpId"]?.jsonPrimitive?.content)
        assertEquals("alice", startBody["userName"]?.jsonPrimitive?.content)

        val finishBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/registration/finish")).jsonObject
        assertEquals("webauthn.create", finishBody["clientDataType"]?.jsonPrimitive?.content)
        assertEquals("https://example.com", finishBody["origin"]?.jsonPrimitive?.content)
    }

    @Test
    fun libraryRoutes_authentication_usesExpectedEndpointsAndPayloadShape() = runTest {
        val requestBodies = mutableMapOf<String, String>()
        val client = createMockClient { request ->
            when (request.url.encodedPath) {
                "/webauthn/authentication/start" -> {
                    requestBodies[request.url.encodedPath] = request.bodyText()
                    respond(
                        content =
                            """
                            {
                              "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "rpId": "example.com",
                              "allowCredentials": []
                            }
                            """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )
                }

                "/webauthn/authentication/finish" -> {
                    requestBodies[request.url.encodedPath] = request.bodyText()
                    respond(
                        content = """{"status":"ok"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )
                }

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.LIBRARY_ROUTES,
        )
        val params = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
            userHandle = "AQID",
        )

        val start = serverClient.getSignInOptions(params)
        assertTrue(start is ValidationResult.Valid)

        val finished = serverClient.finishSignIn(
            params = params,
            response = validAuthenticationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assertTrue(finished)

        val startBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/authentication/start")).jsonObject
        assertEquals("example.com", startBody["rpId"]?.jsonPrimitive?.content)
        assertEquals("alice", startBody["userName"]?.jsonPrimitive?.content)

        val finishBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/authentication/finish")).jsonObject
        assertEquals("webauthn.get", finishBody["clientDataType"]?.jsonPrimitive?.content)
        assertEquals("https://example.com", finishBody["origin"]?.jsonPrimitive?.content)
    }

    @Test
    fun pocStartRegistration_mapsAuthenticatorAttachment() = runTest {
        val client = createMockClient { request ->
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

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )

        val result = serverClient.getRegisterOptions(
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
        val client = createMockClient { request ->
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

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )
        val params = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )

        val start = serverClient.getRegisterOptions(params)
        assertTrue(start is ValidationResult.Valid)

        val finishResult = serverClient.finishRegister(
            params = params,
            response = validRegistrationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

        assertTrue(finishResult)
        val verifyUrl = seenUrls.find { it.contains("/register/verify") }
        assertNotNull(verifyUrl)
        assertTrue(verifyUrl.contains("userId=AQID"))
    }

    @Test
    fun pocStartAuthentication_doesNotCacheUserId_when_registration_verify_fails() = runTest {
        val authOptionBodies = mutableListOf<String>()
        val client = createMockClient { request ->
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
                    content = """{"success":false}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                "/authenticate/options" -> {
                    authOptionBodies += request.bodyText()
                    respond(
                        content =
                            """
                            {
                              "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "rpId": "example.com",
                              "allowCredentials": []
                            }
                            """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )
                }

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )
        val registrationParams = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )

        val start = serverClient.getRegisterOptions(registrationParams)
        assertTrue(start is ValidationResult.Valid)

        val finished = serverClient.finishRegister(
            params = registrationParams,
            response = validRegistrationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assertFalse(finished)

        val authStart = serverClient.getSignInOptions(
            AuthenticationStartPayload(
                rpId = "example.com",
                origin = "https://example.com",
                userName = "alice",
                userHandle = null,
            ),
        )
        assertTrue(authStart is ValidationResult.Valid)
        assertEquals(1, authOptionBodies.size)
        val requestedUserId = Json.parseToJsonElement(authOptionBodies.single())
            .jsonObject["userId"]
            ?.jsonPrimitive
            ?.content
        assertEquals("alice", requestedUserId)
    }

    @Test
    fun pocStartAuthentication_usesCachedUserId_after_successful_registration_verify() = runTest {
        val authOptionBodies = mutableListOf<String>()
        val client = createMockClient { request ->
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

                "/authenticate/options" -> {
                    authOptionBodies += request.bodyText()
                    respond(
                        content =
                            """
                            {
                              "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "rpId": "example.com",
                              "allowCredentials": []
                            }
                            """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )
                }

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )
        val registrationParams = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )

        val start = serverClient.getRegisterOptions(registrationParams)
        assertTrue(start is ValidationResult.Valid)

        val finished = serverClient.finishRegister(
            params = registrationParams,
            response = validRegistrationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assertTrue(finished)

        val authStart = serverClient.getSignInOptions(
            AuthenticationStartPayload(
                rpId = "example.com",
                origin = "https://example.com",
                userName = "alice",
                userHandle = null,
            ),
        )
        assertTrue(authStart is ValidationResult.Valid)
        assertEquals(1, authOptionBodies.size)
        val requestedUserId = Json.parseToJsonElement(authOptionBodies.single())
            .jsonObject["userId"]
            ?.jsonPrimitive
            ?.content
        assertEquals("AQID", requestedUserId)
    }

    private fun createMockClient(
        engineHandler: suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData,
    ): HttpClient {
        return HttpClient(MockEngine { request ->
            engineHandler(request)
        }) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }
    }

    private suspend fun HttpRequestData.bodyText(): String {
        return when (val bodyContent = body) {
            is OutgoingContent.ByteArrayContent -> bodyContent.bytes().decodeToString()
            is OutgoingContent.ReadChannelContent -> bodyContent.readFrom().readRemaining().readText()
            is OutgoingContent.WriteChannelContent -> {
                val channel = ByteChannel(autoFlush = true)
                bodyContent.writeTo(channel)
                channel.close()
                channel.readRemaining().readText()
            }
            is OutgoingContent.NoContent -> ""
            else -> error("Unsupported request body type: ${bodyContent::class}")
        }
    }
}

private fun validRegistrationResponse(): RegistrationResponse {
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
        authenticatorAttachment = AuthenticatorAttachment.PLATFORM,
    )
}

private fun validAuthenticationResponse(): AuthenticationResponse {
    return AuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        rawAuthenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        authenticatorData = AuthenticatorData(
            rpIdHash = ByteArray(32) { 1 },
            flags = 0x01,
            signCount = 2,
        ),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
    )
}
