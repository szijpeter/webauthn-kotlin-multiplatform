package dev.webauthn.server.ktor

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.ValidationResult
import dev.webauthn.server.AttestationPolicy
import dev.webauthn.server.AuthenticationService
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

class WebAuthnKtorRoutesH2StoreTest {

    @OptIn(ExperimentalWebAuthnL3Api::class)
    @Test
    fun registrationAndAuthenticationStartRoutesWorkWithH2BackedStores() = testApplication {
        val adapter = dev.webauthn.server.H2StoreTestAdapter.createTemporary()
        val challengeStore = adapter.challengeStore
        val credentialStore = adapter.credentialStore
        val userStore = adapter.userStore

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = JvmRpIdHasher(),
            attestationPolicy = AttestationPolicy.None,
        )

        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = JvmRpIdHasher(),
        )

        application {
            install(ContentNegotiation) { json() }
            installWebAuthnRoutes(registrationService, authenticationService)
        }

        val registrationStart = client.post("/webauthn/registration/start") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "rpId": "example.com",
                  "rpName": "Example",
                  "origin": "https://example.com",
                  "userName": "h2-user",
                  "userDisplayName": "H2 User",
                  "userHandle": "YWFhYWFhYWFhYWFhYWFhYQ"
                }
                """.trimIndent(),
            )
        }
        assertEquals(HttpStatusCode.OK, registrationStart.status)

        val authenticationStart = client.post("/webauthn/authentication/start") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "rpId": "example.com",
                  "origin": "https://example.com",
                  "userName": "h2-user"
                }
                """.trimIndent(),
            )
        }
        assertEquals(HttpStatusCode.OK, authenticationStart.status)

        adapter.close()
    }
}
