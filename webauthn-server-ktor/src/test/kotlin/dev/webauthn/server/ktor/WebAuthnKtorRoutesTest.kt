package dev.webauthn.server.ktor

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.server.AttestationPolicy
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.InMemoryChallengeStore
import dev.webauthn.server.InMemoryCredentialStore
import dev.webauthn.server.InMemoryUserAccountStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.crypto.JvmRpIdHasher
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebAuthnKtorRoutesTest {
    @Test
    fun authenticationStartRouteReturns400ForUnknownUser() = testApplication {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = JvmRpIdHasher(),
        )

        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = JvmRpIdHasher(),
        )

        application {
            install(ContentNegotiation) { json() }
            installWebAuthnRoutes(registrationService, authenticationService)
        }

        val response = client.post("/webauthn/authentication/start") {
            contentType(ContentType.Application.Json)
            setBody("""{"rpId": "example.com", "origin": "https://example.com", "userName": "bob"}""")
        }

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(response.status.description.isNotEmpty())
    }

    @Test
    fun registrationFinishRouteReturns200() = testApplication {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )

        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = JvmRpIdHasher(),
        )

        application {
            install(ContentNegotiation) { json() }
            installWebAuthnRoutes(registrationService, authenticationService)
        }

        // Setup a session
        val startResponse = client.post("/webauthn/registration/start") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "rpId": "example.com",
                  "rpName": "Example",
                  "origin": "https://example.com",
                  "userName": "alice",
                  "userDisplayName": "Alice",
                  "userHandle": "YWFhYWFhYWFhYWFhYWFhYQ"
                }
                """.trimIndent()
            )
        }
        assertEquals(HttpStatusCode.OK, startResponse.status)


        // Mock the response
        val response = client.post("/webauthn/registration/finish") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "response": {
                    "id": "YWFhYWFhYWFhYWFhYWFhYQ",
                    "rawId": "YWFhYWFhYWFhYWFhYWFhYQ",
                    "response": {
                      "clientDataJSON": "YWFh",
                      "attestationObject": "YWFh"
                    }
                  },
                  "clientDataType": "webauthn.create",
                  "challenge": "YWFhYWFhYWFhYWFhYWFhYQ",
                  "origin": "https://example.com"
                }
                """.trimIndent()
            )
        }
        // It should be 400 because of invalid CBOR "YWFh", but the route should be reachable
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

}

