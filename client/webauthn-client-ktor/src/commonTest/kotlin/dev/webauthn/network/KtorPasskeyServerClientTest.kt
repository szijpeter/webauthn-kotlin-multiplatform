package dev.webauthn.network

import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.PrfExtensionInputDto
import dev.webauthn.serialization.PrfValuesDto
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
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class KtorPasskeyServerClientTest {
    @Test
    fun defaultRoutes_registration_usesExpectedEndpointsAndPayloadShape() = runTest {
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
        assertEquals(PasskeyFinishResult.Verified, finished)

        val startBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/registration/start")).jsonObject
        assertEquals("example.com", startBody["rpId"]?.jsonPrimitive?.content)
        assertEquals("alice", startBody["userName"]?.jsonPrimitive?.content)
        assertTrue("extensions" !in startBody)

        val finishBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/registration/finish")).jsonObject
        assertTrue("clientDataType" !in finishBody)
        assertTrue("challenge" !in finishBody)
        assertTrue("origin" !in finishBody)
    }

    @Test
    fun defaultRoutes_authentication_usesExpectedEndpointsAndPayloadShape() = runTest {
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
        )
        val params = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
        )

        val start = serverClient.getSignInOptions(params)
        assertTrue(start is ValidationResult.Valid)

        val finished = serverClient.finishSignIn(
            params = params,
            response = validAuthenticationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assertEquals(PasskeyFinishResult.Verified, finished)

        val startBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/authentication/start")).jsonObject
        assertEquals("example.com", startBody["rpId"]?.jsonPrimitive?.content)
        assertEquals("alice", startBody["userName"]?.jsonPrimitive?.content)
        assertTrue("userHandle" !in startBody)
        assertTrue("extensions" !in startBody)

        val finishBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/authentication/finish")).jsonObject
        assertTrue("clientDataType" !in finishBody)
        assertTrue("challenge" !in finishBody)
        assertTrue("origin" !in finishBody)
    }

    @Test
    fun customRoutes_overrideDefaultPaths() = runTest {
        val seenPaths = mutableListOf<String>()
        val client = createMockClient { request ->
            seenPaths += request.url.encodedPath
            when (request.url.encodedPath) {
                "/custom/register/start" -> respond(
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

                "/custom/register/finish" -> respond(
                    content = """{"status":"ok"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                "/custom/auth/start" -> respond(
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

                "/custom/auth/finish" -> respond(
                    content = """{"status":"ok"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test/",
            routes = KtorPasskeyRoutes(
                registerOptionsPath = "custom/register/start",
                registerFinishPath = "custom/register/finish",
                signInOptionsPath = "custom/auth/start",
                signInFinishPath = "custom/auth/finish",
            ),
        )
        val registerParams = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )
        val signInParams = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
        )

        assertTrue(serverClient.getRegisterOptions(registerParams) is ValidationResult.Valid)
        assertEquals(
            PasskeyFinishResult.Verified,
            serverClient.finishRegister(
                params = registerParams,
                response = validRegistrationResponse(),
                challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        )
        assertTrue(serverClient.getSignInOptions(signInParams) is ValidationResult.Valid)
        assertEquals(
            PasskeyFinishResult.Verified,
            serverClient.finishSignIn(
                params = signInParams,
                response = validAuthenticationResponse(),
                challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        )

        assertContentEquals(
            [
                "/custom/register/start",
                "/custom/register/finish",
                "/custom/auth/start",
                "/custom/auth/finish",
            ],
            seenPaths,
        )
    }

    @Test
    fun finishRegister_throwsDetailedError_whenServerReturnsValidationPayloadWithoutStatus() = runTest {
        val client = createMockClient { request ->
            when (request.url.encodedPath) {
                "/webauthn/registration/finish" -> respond(
                    content = """{"errors":["invalid payload"]}""",
                    status = HttpStatusCode.BadRequest,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            routes = KtorPasskeyRoutes(
                registerOptionsPath = "/unused/register/start",
                registerFinishPath = "/webauthn/registration/finish",
                signInOptionsPath = "/unused/auth/start",
                signInFinishPath = "/unused/auth/finish",
            ),
        )
        val params = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )

        val failure = assertFailsWith<IllegalStateException> {
            serverClient.finishRegister(
                params = params,
                response = validRegistrationResponse(),
                challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
        }
        assertTrue(failure.message?.contains("Registration finish failed with HTTP 400") == true)
        assertTrue(failure.message?.contains("invalid payload") == true)
    }

    @Test
    fun finishRegister_returnsRejectedResult_whenServerStatusIsNotOk() = runTest {
        val client = createMockClient { request ->
            when (request.url.encodedPath) {
                "/webauthn/registration/finish" -> respond(
                    content = """{"status":"rejected"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }
        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            routes = KtorPasskeyRoutes(
                registerOptionsPath = "/unused/register/start",
                registerFinishPath = "/webauthn/registration/finish",
                signInOptionsPath = "/unused/auth/start",
                signInFinishPath = "/unused/auth/finish",
            ),
        )
        val params = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = "AQID",
        )

        val result = serverClient.finishRegister(
            params = params,
            response = validRegistrationResponse(),
            challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assertTrue(result is PasskeyFinishResult.Rejected)
    }

    @Test
    fun finishSignIn_throwsDetailedError_whenServerReturnsValidationPayloadWithoutStatus() = runTest {
        val client = createMockClient { request ->
            when (request.url.encodedPath) {
                "/webauthn/authentication/finish" -> respond(
                    content = """{"errors":["invalid assertion"]}""",
                    status = HttpStatusCode.BadRequest,
                    headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                )

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            routes = KtorPasskeyRoutes(
                registerOptionsPath = "/unused/register/start",
                registerFinishPath = "/unused/register/finish",
                signInOptionsPath = "/unused/auth/start",
                signInFinishPath = "/webauthn/authentication/finish",
            ),
        )
        val params = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
        )

        val failure = assertFailsWith<IllegalStateException> {
            serverClient.finishSignIn(
                params = params,
                response = validAuthenticationResponse(),
                challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
        }
        assertTrue(failure.message?.contains("Authentication finish failed with HTTP 400") == true)
        assertTrue(failure.message?.contains("invalid assertion") == true)
    }

    @Test
    fun payloadToString_redactsSensitiveUserFields() {
        val registrationPayload = RegistrationStartPayload(
            rpId = "example.com",
            rpName = "Example",
            origin = "https://example.com",
            userName = "alice-sensitive",
            userDisplayName = "Alice Sensitive",
            userHandle = "AQID-sensitive",
        )
        val authPayload = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "bob-sensitive",
        )

        val registrationText = registrationPayload.toString()
        assertTrue(!registrationText.contains("alice-sensitive"))
        assertTrue(!registrationText.contains("Alice Sensitive"))
        assertTrue(!registrationText.contains("AQID-sensitive"))
        assertTrue(registrationText.contains("userName=<redacted>"))
        assertTrue(registrationText.contains("userDisplayName=<redacted>"))
        assertTrue(registrationText.contains("userHandle=<redacted>"))
        assertTrue(registrationText.contains("residentKey=null"))
        assertTrue(registrationText.contains("extensions=none"))

        val authText = authPayload.toString()
        assertTrue(!authText.contains("bob-sensitive"))
        assertTrue(authText.contains("userName=<redacted>"))
        assertTrue(authText.contains("extensions=none"))

        val extensions = AuthenticationExtensionsClientInputsDto(
            prf = PrfExtensionInputDto(
                eval = PrfValuesDto(first = "AQID"),
            ),
        )
        assertTrue(
            RegistrationStartPayload(
                rpId = "example.com",
                rpName = "Example",
                origin = "https://example.com",
                userName = "alice-sensitive",
                userDisplayName = "Alice Sensitive",
                userHandle = "AQID-sensitive",
                residentKey = "required",
                extensions = extensions,
            ).toString()
                .contains("extensions=present"),
        )
        assertTrue(
            AuthenticationStartPayload(
                rpId = "example.com",
                origin = "https://example.com",
                userName = "bob-sensitive",
                extensions = extensions,
            ).toString()
                .contains("extensions=present"),
        )
    }

    @Test
    fun startPayloads_includeExtensions_whenProvided() = runTest {
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

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
        )
        val extensions = AuthenticationExtensionsClientInputsDto(
            prf = PrfExtensionInputDto(
                eval = PrfValuesDto(first = "AQID"),
            ),
        )

        serverClient.getRegisterOptions(
            RegistrationStartPayload(
                rpId = "example.com",
                rpName = "Example",
                origin = "https://example.com",
                userName = "alice",
                userDisplayName = "Alice",
                userHandle = "AQID",
                residentKey = "required",
                extensions = extensions,
            ),
        )
        serverClient.getSignInOptions(
            AuthenticationStartPayload(
                rpId = "example.com",
                origin = "https://example.com",
                userName = "alice",
                extensions = extensions,
            ),
        )

        val registerStartBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/registration/start")).jsonObject
        val authStartBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/authentication/start")).jsonObject
        assertEquals(
            "AQID",
            registerStartBody["extensions"]?.jsonObject
                ?.get("prf")?.jsonObject
                ?.get("eval")?.jsonObject
                ?.get("first")?.jsonPrimitive
                ?.content,
        )
        assertEquals(
            "AQID",
            authStartBody["extensions"]?.jsonObject
                ?.get("prf")?.jsonObject
                ?.get("eval")?.jsonObject
                ?.get("first")?.jsonPrimitive
                ?.content,
        )
        assertEquals("required", registerStartBody["residentKey"]?.jsonPrimitive?.content)
        assertTrue("userHandle" !in authStartBody)
    }

    @Test
    fun authenticationStartPayload_allowsNullUserNameForDiscoverableFlow() = runTest {
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

                else -> error("Unexpected path: ${request.url.encodedPath}")
            }
        }

        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            routes = KtorPasskeyRoutes(
                registerOptionsPath = "/unused/register/start",
                registerFinishPath = "/unused/register/finish",
                signInOptionsPath = "/webauthn/authentication/start",
                signInFinishPath = "/unused/auth/finish",
            ),
        )
        val start = serverClient.getSignInOptions(
            AuthenticationStartPayload(
                rpId = "example.com",
                origin = "https://example.com",
                userName = null,
            ),
        )

        assertTrue(start is ValidationResult.Valid)
        val startBody = Json.parseToJsonElement(requestBodies.getValue("/webauthn/authentication/start")).jsonObject
        assertEquals("example.com", startBody["rpId"]?.jsonPrimitive?.content)
        assertTrue("userName" !in startBody, "userName key should be omitted for discoverable flow")
        assertTrue("userHandle" !in startBody)
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

private fun validRegistrationResponse(): RawRegistrationResponse {
    return RawRegistrationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        authenticatorAttachment = AuthenticatorAttachment.PLATFORM,
    )
}

private fun validAuthenticationResponse(): RawAuthenticationResponse {
    return RawAuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
    )
}
