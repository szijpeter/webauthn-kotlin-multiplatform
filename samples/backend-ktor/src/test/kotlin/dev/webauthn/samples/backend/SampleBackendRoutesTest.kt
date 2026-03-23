package dev.webauthn.samples.backend

import dev.webauthn.server.AttestationPolicy
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.InMemoryChallengeStore
import dev.webauthn.server.InMemoryCredentialStore
import dev.webauthn.server.InMemoryUserAccountStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SampleBackendRoutesTest {
    @Test
    fun sampleBackendRoutesExposeHealthAndAssociationFiles() = testApplication {
        application {
            installSampleBackend(
                registrationService = registrationService(),
                authenticationService = authenticationService(),
                config = SampleBackendConfig(
                    port = 8080,
                    androidPackageName = "dev.webauthn.samples.composepasskey.android",
                    androidSha256 = "AB:CD",
                    iosAppId = "TEAMID.dev.webauthn.samples.composepasskey",
                    attestationPolicy = AttestationPolicy.None,
                ),
            )
        }

        val healthPayload = Json.parseToJsonElement(client.get("/health").bodyAsText()).jsonObject
        assertEquals("ok", healthPayload.getValue("status").jsonPrimitive.content)

        val assetLinksPayload = Json.parseToJsonElement(
            client.get("/.well-known/assetlinks.json").bodyAsText(),
        ).jsonArray
        assertEquals(1, assetLinksPayload.size)
        val relation = assetLinksPayload[0].jsonObject.getValue("relation").jsonArray.map { it.jsonPrimitive.content }
        assertTrue(relation.contains("delegate_permission/common.handle_all_urls"))
        assertTrue(relation.contains("delegate_permission/common.get_login_creds"))
        assertEquals(
            "dev.webauthn.samples.composepasskey.android",
            assetLinksPayload[0].jsonObject
                .getValue("target").jsonObject
                .getValue("package_name").jsonPrimitive.content,
        )

        val wellKnownAasa = Json.parseToJsonElement(
            client.get("/.well-known/apple-app-site-association").bodyAsText(),
        ).jsonObject
        assertEquals(
            "TEAMID.dev.webauthn.samples.composepasskey",
            wellKnownAasa.getValue("webcredentials").jsonObject
                .getValue("apps").jsonArray
                .first()
                .jsonPrimitive.content,
        )

        val rootAasa = Json.parseToJsonElement(
            client.get("/apple-app-site-association").bodyAsText(),
        ).jsonObject
        assertEquals(
            "TEAMID.dev.webauthn.samples.composepasskey",
            rootAasa.getValue("webcredentials").jsonObject
                .getValue("apps").jsonArray
                .first()
                .jsonPrimitive.content,
        )
    }

    @Test
    fun sampleBackendConfigDefaultsToAttestationStrictAndSupportsExplicitNone() {
        val defaultConfig = SampleBackendConfig.fromEnvironment(
            mapOf(
                "PORT" to "9090",
            ),
        )
        assertEquals(9090, defaultConfig.port)
        assertEquals(AttestationPolicy.Strict, defaultConfig.attestationPolicy)
        assertEquals("TEAMID.com.example.app", defaultConfig.iosAppId)
        assertTrue(defaultConfig.iosAppIdWarning?.contains("placeholder") == true)

        val strictConfig = SampleBackendConfig.fromEnvironment(
            mapOf(
                "WEBAUTHN_SAMPLE_ATTESTATION" to "STRICT",
            ),
        )
        assertEquals(AttestationPolicy.Strict, strictConfig.attestationPolicy)

        val noneConfig = SampleBackendConfig.fromEnvironment(
            mapOf(
                "WEBAUTHN_SAMPLE_ATTESTATION" to "NONE",
            ),
        )
        assertEquals(AttestationPolicy.None, noneConfig.attestationPolicy)

        val unknownConfig = SampleBackendConfig.fromEnvironment(
            mapOf(
                "WEBAUTHN_SAMPLE_ATTESTATION" to "oops",
            ),
        )
        assertEquals(AttestationPolicy.Strict, unknownConfig.attestationPolicy)

        val explicitIosAppId = SampleBackendConfig.fromEnvironment(
            mapOf(
                "IOS_APP_ID" to "ABCD1234.com.example.demo",
            ),
        )
        assertEquals("ABCD1234.com.example.demo", explicitIosAppId.iosAppId)
        assertNull(explicitIosAppId.iosAppIdWarning)

        val derivedIosAppId = SampleBackendConfig.fromEnvironment(
            mapOf(
                "IOS_TEAM_ID" to "ABCD1234",
                "IOS_BUNDLE_ID" to "com.example.demo",
            ),
        )
        assertEquals("ABCD1234.com.example.demo", derivedIosAppId.iosAppId)
        assertNull(derivedIosAppId.iosAppIdWarning)

        val partiallyConfiguredIosAppId = SampleBackendConfig.fromEnvironment(
            mapOf(
                "IOS_TEAM_ID" to "ABCD1234",
            ),
        )
        assertEquals("TEAMID.com.example.app", partiallyConfiguredIosAppId.iosAppId)
        assertTrue(partiallyConfiguredIosAppId.iosAppIdWarning?.contains("both IOS_TEAM_ID and IOS_BUNDLE_ID") == true)
    }
}

private fun registrationService(): RegistrationService {
    val challengeStore = InMemoryChallengeStore()
    val credentialStore = InMemoryCredentialStore()
    val userStore = InMemoryUserAccountStore()
    return RegistrationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        attestationVerifier = StrictAttestationVerifier(),
        rpIdHasher = JvmRpIdHasher(),
        attestationPolicy = AttestationPolicy.None,
    )
}

private fun authenticationService(): AuthenticationService {
    val challengeStore = InMemoryChallengeStore()
    val credentialStore = InMemoryCredentialStore()
    val userStore = InMemoryUserAccountStore()
    return AuthenticationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        signatureVerifier = JvmSignatureVerifier(),
        rpIdHasher = JvmRpIdHasher(),
    )
}
