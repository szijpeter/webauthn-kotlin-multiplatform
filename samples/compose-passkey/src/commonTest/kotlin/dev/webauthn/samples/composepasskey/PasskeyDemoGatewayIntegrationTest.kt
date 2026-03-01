package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PasskeyDemoGatewayIntegrationTest {
    @Test
    fun health_success_and_failure_are_mapped() = runTest {
        val healthyGateway = gatewayWithEngine(
            client = FakePasskeyClient(),
            engine = MockEngine { request ->
                when {
                    request.method == HttpMethod.Get && request.url.encodedPath == "/health" -> respond(
                        content = """{"status":"ok"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    else -> error("Unexpected route ${request.method.value} ${request.url.encodedPath}")
                }
            },
        )
        val healthy = healthyGateway.checkHealth(PasskeyDemoConfig(endpointBase = "https://example.test"))
        assertTrue(healthy is PasskeyDemoActionResult.Success)

        val unhealthyGateway = gatewayWithEngine(
            client = FakePasskeyClient(),
            engine = MockEngine { request ->
                when {
                    request.method == HttpMethod.Get && request.url.encodedPath == "/health" -> respond(
                        content = """{"status":"down"}""",
                        status = HttpStatusCode.InternalServerError,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    else -> error("Unexpected route ${request.method.value} ${request.url.encodedPath}")
                }
            },
        )
        val unhealthy = unhealthyGateway.checkHealth(PasskeyDemoConfig(endpointBase = "https://example.test"))
        assertTrue(unhealthy is PasskeyDemoActionResult.Failure)
        val failure = unhealthy
        assertEquals(PasskeyDemoErrorCategory.TRANSPORT, failure.category)
        assertTrue(failure.message.contains("HTTP 500"))
    }

    @Test
    fun register_success_orchestrates_options_create_verify() = runTest {
        val seenRoutes = mutableListOf<String>()
        val engine = MockEngine { request ->
                seenRoutes += "${request.method.value} ${request.url.encodedPath}"
                when {
                    request.method == HttpMethod.Post && request.url.encodedPath == "/register/options" -> respond(
                        content = """
                            {
                              "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "rp": {"id": "localhost", "name": "Example"},
                              "user": {"id": "AQID", "name": "demo@local", "displayName": "Demo User"},
                              "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                              "timeout": 60000
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    request.method == HttpMethod.Post && request.url.encodedPath == "/register/verify" -> respond(
                        content = """{"success":true}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    else -> error("Unexpected route ${request.method.value} ${request.url.encodedPath}")
                }
            }
        val gateway = gatewayWithEngine(
            client = FakePasskeyClient(registerResult = PasskeyResult.Success(validRegistrationResponse())),
            engine = engine,
        )

        val result = gateway.register(PasskeyDemoConfig(endpointBase = "https://example.test"))

        assertTrue(result is PasskeyDemoActionResult.Success)
        assertEquals(
            listOf("POST /register/options", "POST /register/verify"),
            seenRoutes,
        )
    }

    @Test
    fun authenticate_success_orchestrates_options_assert_verify() = runTest {
        val seenRoutes = mutableListOf<String>()
        val engine = MockEngine { request ->
                seenRoutes += "${request.method.value} ${request.url.encodedPath}"
                when {
                    request.method == HttpMethod.Post && request.url.encodedPath == "/authenticate/options" -> respond(
                        content = """
                            {
                              "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "rpId": "localhost",
                              "timeout": 60000,
                              "allowCredentials": [{"type":"public-key","id":"MzMzMzMzMzMzMzMzMzMzMw"}]
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    request.method == HttpMethod.Post && request.url.encodedPath == "/authenticate/verify" -> respond(
                        content = """{"success":true}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    else -> error("Unexpected route ${request.method.value} ${request.url.encodedPath}")
                }
            }
        val gateway = gatewayWithEngine(
            client = FakePasskeyClient(authResult = PasskeyResult.Success(validAuthenticationResponse())),
            engine = engine,
        )

        val result = gateway.authenticate(PasskeyDemoConfig(endpointBase = "https://example.test"))

        assertTrue(result is PasskeyDemoActionResult.Success)
        assertEquals(
            listOf("POST /authenticate/options", "POST /authenticate/verify"),
            seenRoutes,
        )
    }

    @Test
    fun register_validation_invalid_returns_validation_failure() = runTest {
        val gateway = gatewayWithEngine(
            client = FakePasskeyClient(),
            engine = MockEngine { request ->
                when {
                    request.method == HttpMethod.Post && request.url.encodedPath == "/register/options" -> respond(
                        content = """
                            {
                              "challenge": "not_base64!",
                              "rp": {"id": "localhost", "name": "Example"},
                              "user": {"id": "AQID", "name": "demo@local", "displayName": "Demo User"},
                              "pubKeyCredParams": []
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    else -> error("Unexpected route ${request.method.value} ${request.url.encodedPath}")
                }
            },
        )

        val result = gateway.register(PasskeyDemoConfig(endpointBase = "https://example.test"))

        assertTrue(result is PasskeyDemoActionResult.Failure)
        val failure = result
        assertEquals(PasskeyDemoErrorCategory.VALIDATION, failure.category)
        assertTrue(failure.message.contains("validation failed"))
    }

    @Test
    fun register_platform_failure_returns_platform_category() = runTest {
        val gateway = gatewayWithEngine(
            client = FakePasskeyClient(
                registerResult = PasskeyResult.Failure(
                    PasskeyClientError.Platform("createCredentialAsync no provider dependencies found"),
                ),
            ),
            engine = MockEngine { request ->
                when {
                    request.method == HttpMethod.Post && request.url.encodedPath == "/register/options" -> respond(
                        content = """
                            {
                              "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "rp": {"id": "localhost", "name": "Example"},
                              "user": {"id": "AQID", "name": "demo@local", "displayName": "Demo User"},
                              "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf("Content-Type", ContentType.Application.Json.toString()),
                    )

                    else -> error("Unexpected route ${request.method.value} ${request.url.encodedPath}")
                }
            },
        )

        val result = gateway.register(PasskeyDemoConfig(endpointBase = "https://example.test"))

        assertTrue(result is PasskeyDemoActionResult.Failure)
        val failure = result
        assertEquals(PasskeyDemoErrorCategory.PLATFORM, failure.category)
        assertTrue(failure.message.contains("credentials-play-services-auth"))
    }

    @Test
    fun sanitize_network_log_line_redacts_sensitive_fields() {
        val line = """
            POST /register/verify body={"challenge":"abc123","clientDataJSON":"payload","signature":"sig123"} query=challenge=abc123&id=cred-1
        """.trimIndent()

        val sanitized = sanitizeNetworkLogLine(line)

        assertTrue(sanitized.contains("\"challenge\":\"<redacted:6>\""))
        assertTrue(sanitized.contains("\"clientDataJSON\":\"<redacted:7>\""))
        assertTrue(sanitized.contains("challenge=<redacted:6>"))
        assertTrue(sanitized.contains("id=<redacted:6>"))
    }
}

private fun gatewayWithEngine(
    client: PasskeyClient,
    engine: MockEngine,
): DefaultPasskeyDemoGateway {
    val httpClient = HttpClient(engine) {
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
    }
    return DefaultPasskeyDemoGateway(
        passkeyClient = client,
        httpClient = httpClient,
        diagnostics = TestDiagnostics(),
    )
}

private class FakePasskeyClient(
    private val registerResult: PasskeyResult<RegistrationResponse> = PasskeyResult.Success(validRegistrationResponse()),
    private val authResult: PasskeyResult<AuthenticationResponse> = PasskeyResult.Success(validAuthenticationResponse()),
) : PasskeyClient {
    override suspend fun createCredential(
        options: dev.webauthn.model.PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> = registerResult

    override suspend fun getAssertion(
        options: dev.webauthn.model.PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> = authResult

    override suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities(supportsSecurityKey = true)
}

private class TestDiagnostics : PasskeyDemoDiagnostics {
    override fun trace(event: String, fields: Map<String, String>) = Unit

    override fun error(
        event: String,
        message: String,
        throwable: Throwable?,
        fields: Map<String, String>,
    ) = Unit
}

private fun validRegistrationResponse(): RegistrationResponse {
    val mapped = WebAuthnDtoMapper.toModel(
        RegistrationResponseDto(
            id = "MzMzMzMzMzMzMzMzMzMzMw",
            rawId = "MzMzMzMzMzMzMzMzMzMzMw",
            response = RegistrationResponsePayloadDto(
                clientDataJson = "BAUG",
                attestationObject = "o2NmbXRkbm9uZWhhdXRoRGF0YVhKRERERERERERERERERERERERERERERERERERERERERERBAAAACVVVVVVVVVVVVVVVVVVVVVUAEDMzMzMzMzMzMzMzMzMzMzOhAQJnYXR0U3RtdKA",
            ),
        ),
    )
    return when (mapped) {
        is ValidationResult.Valid -> mapped.value
        is ValidationResult.Invalid -> error("Invalid test registration response mapping: ${mapped.errors}")
    }
}

private fun validAuthenticationResponse(): AuthenticationResponse {
    val mapped = WebAuthnDtoMapper.toModel(
        AuthenticationResponseDto(
            id = "MzMzMzMzMzMzMzMzMzMzMw",
            rawId = "MzMzMzMzMzMzMzMzMzMzMw",
            response = AuthenticationResponsePayloadDto(
                clientDataJson = "AQID",
                authenticatorData = "REREREREREREREREREREREREREREREREREREREREREQFAAAAKg",
                signature = "CQkJ",
            ),
        ),
    )
    return when (mapped) {
        is ValidationResult.Valid -> mapped.value
        is ValidationResult.Invalid -> error("Invalid test authentication response mapping: ${mapped.errors}")
    }
}
