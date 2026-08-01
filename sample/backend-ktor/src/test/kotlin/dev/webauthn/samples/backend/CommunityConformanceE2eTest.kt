package dev.webauthn.samples.backend

import dev.webauthn.client.DefaultJsonPasskeyClient
import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.KtorPasskeyRoutes
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import dev.webauthn.server.AttestationPolicy
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.InMemoryChallengeStore
import dev.webauthn.server.InMemoryCredentialStore
import dev.webauthn.server.InMemoryUserAccountStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CommunityConformanceE2eTest {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
    }

    @Test
    fun attestationOptionsMatchCommunityConformanceContract() = testApplication {
        val services = backendServices()
        application {
            installSampleBackend(
                registrationService = services.registrationService,
                authenticationService = services.authenticationService,
                config = sampleConfig(),
            )
        }

        val request = communityOptionsRequest(
            username = "2cKNGn1rOXC5_C0yR08W",
            displayName = "Lakeesha Hemstreet",
            attestation = "direct",
        )
        val response = client.post("/attestation/options") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val responseBody = Json.parseToJsonElement(response.bodyAsText()).jsonObject

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("ok", responseBody.getValue("status").jsonPrimitive.content)
        assertEquals("", responseBody.getValue("errorMessage").jsonPrimitive.content)
        assertEquals("2cKNGn1rOXC5_C0yR08W", responseBody.getValue("user").jsonObject.getValue("name").jsonPrimitive.content)
        assertEquals("Lakeesha Hemstreet", responseBody.getValue("user").jsonObject.getValue("displayName").jsonPrimitive.content)
        assertTrue(responseBody.getValue("user").jsonObject.getValue("id").jsonPrimitive.content.matches(BASE64_URL_REGEX))
        assertEquals(FIXTURE_RP_ID, responseBody.getValue("rp").jsonObject.getValue("id").jsonPrimitive.content)
        assertEquals(FIXTURE_RP_ID, responseBody.getValue("rp").jsonObject.getValue("name").jsonPrimitive.content)
        assertTrue(responseBody.getValue("challenge").jsonPrimitive.content.matches(BASE64_URL_REGEX))
        assertTrue(responseBody.getValue("pubKeyCredParams").jsonArray.isNotEmpty())
        assertEquals("direct", responseBody.getValue("attestation").jsonPrimitive.content)
        assertEquals(
            false.toString(),
            responseBody.getValue("authenticatorSelection").jsonObject
                .getValue("requireResidentKey")
                .jsonPrimitive
                .content,
        )
        assertEquals(
            "preferred",
            responseBody.getValue("authenticatorSelection").jsonObject
                .getValue("userVerification")
                .jsonPrimitive
                .content,
        )
        assertEquals(
            "true",
            responseBody.getValue("extensions").jsonObject
                .getValue("example.extension")
                .jsonPrimitive
                .content,
        )

        val secondResponse = client.post("/attestation/options") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val secondBody = Json.parseToJsonElement(secondResponse.bodyAsText()).jsonObject
        assertNotEquals(
            responseBody.getValue("challenge").jsonPrimitive.content,
            secondBody.getValue("challenge").jsonPrimitive.content,
        )
    }

    @Test
    fun directRegistrationE2eUsesSharedClientAndJsonFacade() = testApplication {
        val services = backendServices()
        application {
            installSampleBackend(
                registrationService = services.registrationService,
                authenticationService = services.authenticationService,
                config = sampleConfig(),
            )
        }
        val httpClient = createClient {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val optionsResponse = httpClient.post("/attestation/options") {
            contentType(ContentType.Application.Json)
            setBody(
                communityOptionsRequest(
                    username = "arthur",
                    displayName = "Arthur Dent",
                    attestation = "none",
                    useLegacyResidentKey = false,
                ),
            )
        }
        val optionsJson = optionsResponse.bodyAsText()
        val jsonClient = DefaultJsonPasskeyClient(
            passkeyClient = DefaultPasskeyClient(FixtureRegistrationBridge(FIXTURE_ORIGIN)),
        )
        val credentialJson = when (val result = jsonClient.createCredentialJson(optionsJson)) {
            is PasskeyResult.Success -> result.value
            is PasskeyResult.Failure -> error("Client registration failed: ${result.error.message}")
        }

        val finishResponse = httpClient.post("/attestation/result") {
            contentType(ContentType.Application.Json)
            setBody(credentialJson)
        }
        val finishBody = Json.parseToJsonElement(finishResponse.bodyAsText()).jsonObject

        assertEquals(HttpStatusCode.OK, finishResponse.status)
        assertEquals("ok", finishBody.getValue("status").jsonPrimitive.content)
        assertEquals(FIXTURE_CREDENTIAL_ID, finishBody.getValue("credentialId").jsonPrimitive.content)
    }

    @Test
    fun ktorNetworkClientCanRunRegistrationThroughConformanceRouteOverrides() = testApplication {
        val services = backendServices()
        application {
            installSampleBackend(
                registrationService = services.registrationService,
                authenticationService = services.authenticationService,
                config = sampleConfig(),
            )
        }
        val httpClient = createClient {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val serverClient = KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = "",
            routes = KtorPasskeyRoutes(
                registerOptionsPath = "/attestation/options",
                registerFinishPath = "/attestation/result",
            ),
        )
        val startPayload = RegistrationStartPayload(
            rpId = FIXTURE_RP_ID,
            rpName = FIXTURE_RP_ID,
            origin = FIXTURE_ORIGIN,
            userName = "ford",
            userDisplayName = "Ford Prefect",
            userHandle = Base64UrlBytes.fromBytes("ford".encodeToByteArray()).encoded(),
        )
        val options = when (val result = serverClient.getRegisterOptions(startPayload)) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> error("Registration options were invalid: ${result.errors}")
        }
        val response = when (
            val result = DefaultPasskeyClient(FixtureRegistrationBridge(FIXTURE_ORIGIN))
                .createCredential(options)
        ) {
            is PasskeyResult.Success -> result.value
            is PasskeyResult.Failure -> error("Client registration failed: ${result.error.message}")
        }

        val finish = serverClient.finishRegister(
            params = startPayload,
            response = response,
            challengeAsBase64Url = options.challenge.value.encoded(),
        )

        assertEquals(dev.webauthn.client.PasskeyFinishResult.Verified, finish)
    }

    private fun backendServices(): BackendServices {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        return BackendServices(
            registrationService = RegistrationService(
                challengeStore = challengeStore,
                credentialStore = credentialStore,
                userAccountStore = userStore,
                attestationVerifier = StrictAttestationVerifier(),
                rpIdHasher = JvmRpIdHasher(),
                attestationPolicy = AttestationPolicy.None,
            ),
            authenticationService = AuthenticationService(
                challengeStore = challengeStore,
                credentialStore = credentialStore,
                userAccountStore = userStore,
                signatureVerifier = JvmSignatureVerifier(),
                rpIdHasher = JvmRpIdHasher(),
            ),
        )
    }

    private fun sampleConfig(): SampleBackendConfig =
        SampleBackendConfig(
            attestationPolicy = AttestationPolicy.None,
            conformanceRpId = FIXTURE_RP_ID,
            conformanceOrigin = FIXTURE_ORIGIN,
        )

    private fun communityOptionsRequest(
        username: String,
        displayName: String,
        attestation: String,
        useLegacyResidentKey: Boolean = true,
    ): String =
        buildJsonObject {
            put("username", username)
            put("displayName", displayName)
            put("attestation", attestation)
            put(
                "authenticatorSelection",
                buildJsonObject {
                    if (useLegacyResidentKey) {
                        put("requireResidentKey", false)
                    } else {
                        put("residentKey", "preferred")
                    }
                    put("userVerification", "preferred")
                },
            )
            put(
                "extensions",
                buildJsonObject {
                    put("example.extension", true)
                },
            )
        }.toString()

    private inner class FixtureRegistrationBridge(
        private val origin: String,
    ) : PasskeyPlatformBridge {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
            val dto = RegistrationResponseDto(
                id = FIXTURE_CREDENTIAL_ID,
                rawId = FIXTURE_CREDENTIAL_ID,
                response = RegistrationResponsePayloadDto(
                    clientDataJson = clientDataJson(
                        type = "webauthn.create",
                        challenge = options.challenge.value.encoded(),
                        origin = origin,
                    ),
                    attestationObject = FIXTURE_ATTESTATION_OBJECT,
                ),
            )
            return when (val result = WebAuthnDtoMapper.toModel(dto)) {
                is ValidationResult.Valid -> result.value
                is ValidationResult.Invalid -> error("Fixture registration response is invalid: ${result.errors}")
            }
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
            error("Assertion generation needs a signing software authenticator and is intentionally outside this first CI slice.")
        }

        override fun mapPlatformError(throwable: Throwable): PasskeyClientError =
            PasskeyClientError.Platform(throwable.message ?: "fixture bridge failure", throwable)

        override suspend fun capabilities(): PasskeyCapabilities =
            PasskeyCapabilities()

        private fun clientDataJson(
            type: String,
            challenge: String,
            origin: String,
        ): String {
            val rawJson = json.encodeToString(
                buildJsonObject {
                    put("type", type)
                    put("challenge", challenge)
                    put("origin", origin)
                },
            )
            return Base64UrlBytes.fromBytes(rawJson.encodeToByteArray()).encoded()
        }
    }

    private companion object {
        private val BASE64_URL_REGEX = Regex("^[a-zA-Z0-9_-]+$")
        private const val FIXTURE_RP_ID = "nella-intercrinal-cryptically.ngrok-free.dev"
        private const val FIXTURE_ORIGIN = "android:apk-key-hash:Vbj-mPe9x0NEiHDGG3EOi04ETGT5SIoEc3f2zpc7qC8"
        private const val FIXTURE_CREDENTIAL_ID = "adnJdzQQOzHT8aobzfRCfA"
        private const val FIXTURE_ATTESTATION_OBJECT =
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWpdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEGnZyXc0EDsx0_GqG830QnylAQIDJiABIVggd-XJL5odWHADN7Ayg5vk1LfCsAGqC9gpXHMtgtehFjoiWCAnkr58JQNicaTRIf7zALTm0G5Jh1BSTjlfi0HE05IyDA"
    }
}

private data class BackendServices(
    val registrationService: RegistrationService,
    val authenticationService: AuthenticationService,
)
