package dev.webauthn.network

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpIdHash
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
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class KtorPasskeyServerClientTest {
    @Test
    fun defaultContract_registration_usesExpectedEndpointsAndPayloadShape() = runTest {
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
            backendContract = DefaultBackendContract(),
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
    fun defaultContract_authentication_usesExpectedEndpointsAndPayloadShape() = runTest {
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
            backendContract = DefaultBackendContract(),
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
    fun customRoutes_overrideDefaultContractPaths() = runTest {
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
            backendContract = DefaultBackendContract(
                registerOptionsPath = "custom/register/start",
                registerVerifyPath = "custom/register/finish",
                authenticateOptionsPath = "custom/auth/start",
                authenticateVerifyPath = "custom/auth/finish",
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
            userHandle = "AQID",
        )

        assertTrue(serverClient.getRegisterOptions(registerParams) is ValidationResult.Valid)
        assertTrue(
            serverClient.finishRegister(
                params = registerParams,
                response = validRegistrationResponse(),
                challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        )
        assertTrue(serverClient.getSignInOptions(signInParams) is ValidationResult.Valid)
        assertTrue(
            serverClient.finishSignIn(
                params = signInParams,
                response = validAuthenticationResponse(),
                challengeAsBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        )

        assertContentEquals(
            listOf(
                "/custom/register/start",
                "/custom/register/finish",
                "/custom/auth/start",
                "/custom/auth/finish",
            ),
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

        val contract = DefaultBackendContract(
            registerOptionsPath = "/unused/register/start",
            registerVerifyPath = "/webauthn/registration/finish",
            authenticateOptionsPath = "/unused/auth/start",
            authenticateVerifyPath = "/unused/auth/finish",
        )
        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            backendContract = contract,
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

        val contract = DefaultBackendContract(
            registerOptionsPath = "/unused/register/start",
            registerVerifyPath = "/unused/register/finish",
            authenticateOptionsPath = "/unused/auth/start",
            authenticateVerifyPath = "/webauthn/authentication/finish",
        )
        val serverClient = KtorPasskeyServerClient(
            httpClient = client,
            endpointBase = "https://example.test",
            backendContract = contract,
        )
        val params = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
            userHandle = "AQID",
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
            rpIdHash = rpIdHash(1),
            flags = 0x41,
            signCount = 1,
        ),
        attestedCredentialData = AttestedCredentialData(
            aaguid = aaguid(2),
            credentialId = CredentialId.fromBytes(byteArrayOf(9, 9, 9)),
            cosePublicKey = base64UrlBytes(1, 2, 3),
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
            rpIdHash = rpIdHash(1),
            flags = 0x01,
            signCount = 2,
        ),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
    )
}

private fun rpIdHash(seed: Int): RpIdHash = RpIdHash.fromBytes(ByteArray(32) { seed.toByte() })

private fun aaguid(seed: Int): Aaguid = Aaguid.fromBytes(ByteArray(16) { seed.toByte() })

private fun base64UrlBytes(vararg value: Int): Base64UrlBytes =
    Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })
