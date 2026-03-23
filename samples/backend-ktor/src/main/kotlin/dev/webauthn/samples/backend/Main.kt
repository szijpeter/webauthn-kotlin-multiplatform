@file:Suppress("LongMethod")

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
import dev.webauthn.server.ktor.installWebAuthnRoutes
import io.ktor.http.ContentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.plugins.statuspages.exception
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

private const val DEFAULT_PORT: Int = 8080
private const val DEFAULT_ANDROID_PACKAGE_NAME: String = "dev.webauthn.samples.composepasskey.android"
private const val DEFAULT_ANDROID_SHA256: String = "PUT_SHA256_FINGERPRINT_HERE"
private const val DEFAULT_IOS_APP_ID: String = "TEAMID.com.example.app"

public fun main(): Unit {
    val config = SampleBackendConfig.fromEnvironment()
    config.iosAppIdWarning?.let { warning ->
        println("WARNING: $warning")
    }
    val challengeStore = InMemoryChallengeStore()
    val credentialStore = InMemoryCredentialStore()
    val userStore = InMemoryUserAccountStore()

    val registrationService = RegistrationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        attestationVerifier = StrictAttestationVerifier(),
        rpIdHasher = JvmRpIdHasher(),
        attestationPolicy = config.attestationPolicy,
    )

    val authenticationService = AuthenticationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        signatureVerifier = JvmSignatureVerifier(),
        rpIdHasher = JvmRpIdHasher(),
    )

    embeddedServer(Netty, port = config.port) {
        installSampleBackend(registrationService, authenticationService, config)
    }.start(wait = true)
}

public fun Application.installSampleBackend(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
    config: SampleBackendConfig,
): Unit {
    install(ContentNegotiation) {
        json()
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            val message = cause.message ?: cause::class.simpleName ?: "Unexpected error"
            call.application.environment.log.error("Unhandled backend error", cause)
            call.respond(
                status = io.ktor.http.HttpStatusCode.InternalServerError,
                message = mapOf("errors" to listOf("internal: $message")),
            )
        }
    }
    installWebAuthnRoutes(registrationService, authenticationService)
    routing {
        get("/health") {
            call.respond(HttpStatusPayload(status = "ok"))
        }
        get("/.well-known/assetlinks.json") {
            call.respond(
                listOf(
                    AssetLinksStatement(
                        relation = listOf(
                            "delegate_permission/common.handle_all_urls",
                            "delegate_permission/common.get_login_creds",
                        ),
                        target = AssetLinksTarget(
                            namespace = "android_app",
                            packageName = config.androidPackageName,
                            sha256CertFingerprints = listOf(config.androidSha256),
                        ),
                    ),
                ),
            )
        }
        get("/.well-known/apple-app-site-association") {
            call.respond(
                AppleAppSiteAssociation(
                    applinks = emptyMap(),
                    webcredentials = AppleWebCredentials(apps = listOf(config.iosAppId)),
                    appclips = emptyMap(),
                ),
            )
        }
        get("/apple-app-site-association") {
            call.respond(
                AppleAppSiteAssociation(
                    applinks = emptyMap(),
                    webcredentials = AppleWebCredentials(apps = listOf(config.iosAppId)),
                    appclips = emptyMap(),
                ),
            )
        }
        get("/") {
            call.respondText(
                text = buildString {
                    appendLine("WebAuthn Kotlin MPP sample backend server")
                    appendLine("PORT=${config.port}")
                    appendLine("ANDROID_PACKAGE_NAME=${config.androidPackageName}")
                    appendLine("IOS_APP_ID=${config.iosAppId}")
                    appendLine("AttestationPolicy=${config.attestationPolicy}")
                    config.iosAppIdWarning?.let { warning ->
                        appendLine("WARNING=$warning")
                    }
                    appendLine()
                    appendLine("Routes:")
                    appendLine("POST /webauthn/registration/start")
                    appendLine("POST /webauthn/registration/finish")
                    appendLine("POST /webauthn/authentication/start")
                    appendLine("POST /webauthn/authentication/finish")
                    appendLine("GET  /health")
                    appendLine("GET  /.well-known/assetlinks.json")
                    appendLine("GET  /.well-known/apple-app-site-association")
                    appendLine("GET  /apple-app-site-association")
                },
                contentType = ContentType.Text.Plain,
            )
        }
    }
}

public data class SampleBackendConfig(
    val port: Int = DEFAULT_PORT,
    val androidPackageName: String = DEFAULT_ANDROID_PACKAGE_NAME,
    val androidSha256: String = DEFAULT_ANDROID_SHA256,
    val iosAppId: String = DEFAULT_IOS_APP_ID,
    val iosAppIdWarning: String? = null,
    val attestationPolicy: AttestationPolicy = AttestationPolicy.Strict,
) {
    public companion object {
        public fun fromEnvironment(environment: Map<String, String> = System.getenv()): SampleBackendConfig {
            val configuredPort = environment["PORT"]?.toIntOrNull() ?: DEFAULT_PORT
            val configuredAndroidPackageName = environment["ANDROID_PACKAGE_NAME"].orIfBlank(DEFAULT_ANDROID_PACKAGE_NAME)
            val configuredAndroidSha256 = environment["ANDROID_SHA256"].orIfBlank(DEFAULT_ANDROID_SHA256)
            val configuredIosAppId = resolveIosAppIdConfig(environment)
            val attestationMode = environment["WEBAUTHN_SAMPLE_ATTESTATION"].orIfBlank("STRICT")
            val attestationPolicy = when (attestationMode.uppercase()) {
                "NONE" -> AttestationPolicy.None
                else -> AttestationPolicy.Strict
            }
            return SampleBackendConfig(
                port = configuredPort,
                androidPackageName = configuredAndroidPackageName,
                androidSha256 = configuredAndroidSha256,
                iosAppId = configuredIosAppId.appId,
                iosAppIdWarning = configuredIosAppId.warning,
                attestationPolicy = attestationPolicy,
            )
        }

        private fun resolveIosAppIdConfig(environment: Map<String, String>): IosAppIdConfig {
            val explicitAppId = environment["IOS_APP_ID"]?.trim().orEmpty()
            if (explicitAppId.isNotEmpty()) {
                return IosAppIdConfig(
                    appId = explicitAppId,
                    warning = null,
                )
            }

            val teamId = environment["IOS_TEAM_ID"]?.trim().orEmpty()
            val bundleId = environment["IOS_BUNDLE_ID"]?.trim().orEmpty()
            if (teamId.isNotEmpty() && bundleId.isNotEmpty()) {
                return IosAppIdConfig(
                    appId = "$teamId.$bundleId",
                    warning = null,
                )
            }

            val warning = when {
                teamId.isNotEmpty() || bundleId.isNotEmpty() ->
                    "IOS_APP_ID is not set. Provide both IOS_TEAM_ID and IOS_BUNDLE_ID (or set IOS_APP_ID directly) to generate a valid apple-app-site-association app id."
                else ->
                    "IOS_APP_ID is using placeholder TEAMID.com.example.app. Real iOS passkey E2E requires IOS_APP_ID (or IOS_TEAM_ID + IOS_BUNDLE_ID) to match your signed app."
            }
            return IosAppIdConfig(
                appId = DEFAULT_IOS_APP_ID,
                warning = warning,
            )
        }
    }
}

private data class IosAppIdConfig(
    val appId: String,
    val warning: String?,
)

@Serializable
private data class HttpStatusPayload(
    val status: String,
)

@Serializable
private data class AssetLinksStatement(
    val relation: List<String>,
    val target: AssetLinksTarget,
)

@Serializable
private data class AssetLinksTarget(
    val namespace: String,
    @SerialName("package_name") val packageName: String,
    @SerialName("sha256_cert_fingerprints") val sha256CertFingerprints: List<String>,
)

@Serializable
private data class AppleAppSiteAssociation(
    val applinks: Map<String, String> = emptyMap(),
    val webcredentials: AppleWebCredentials,
    val appclips: Map<String, String> = emptyMap(),
)

@Serializable
private data class AppleWebCredentials(
    val apps: List<String>,
)

private fun String?.orIfBlank(default: String): String {
    val value = this?.trim()
    return if (value.isNullOrEmpty()) default else value
}
