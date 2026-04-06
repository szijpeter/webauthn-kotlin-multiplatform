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
        get("/webauthn/cli/browser") {
            call.respondText(
                text = PASSKEY_CLI_BROWSER_BRIDGE_PAGE,
                contentType = ContentType.Text.Html,
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
                    appendLine("GET  /webauthn/cli/browser")
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
        public fun fromEnvironment(
            environment: Map<String, String> = System.getenv()
        ): SampleBackendConfig {
            val configuredPort = environment["PORT"]?.toIntOrNull() ?: DEFAULT_PORT
            val configuredAndroidPackageName = environment["ANDROID_PACKAGE_NAME"]
                .orIfBlank(DEFAULT_ANDROID_PACKAGE_NAME)
            val configuredAndroidSha256 = environment["ANDROID_SHA256"]
                .orIfBlank(DEFAULT_ANDROID_SHA256)
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

private const val PASSKEY_CLI_BROWSER_BRIDGE_PAGE: String =
    """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Passkey CLI Browser Bridge</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 42rem; line-height: 1.45; padding: 0 1rem; }
    h1 { font-size: 1.4rem; margin-bottom: .5rem; }
    code { background: #f3f4f6; border-radius: 4px; padding: 0 .25rem; }
    .status { margin-top: 1rem; padding: .75rem 1rem; border-radius: 6px; background: #eef2ff; }
    .error { background: #fee2e2; color: #7f1d1d; }
  </style>
</head>
<body>
  <h1>Passkey CLI Browser Handoff</h1>
  <p id="summary">Preparing browser passkey ceremony...</p>
  <div id="status" class="status">Loading...</div>
  <script>
    const params = new URLSearchParams(window.location.search);
    const callbackBase = params.get("callback");
    const token = params.get("token");
    const command = params.get("command");
    const summaryEl = document.getElementById("summary");
    const statusEl = document.getElementById("status");

    function setStatus(message, isError = false) {
      statusEl.textContent = message;
      statusEl.className = isError ? "status error" : "status";
    }

    function b64urlToBytes(value) {
      if (typeof value !== "string") return value;
      const padded = value + "=".repeat((4 - value.length % 4) % 4);
      const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
      const decoded = atob(b64);
      const bytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i += 1) {
        bytes[i] = decoded.charCodeAt(i);
      }
      return bytes;
    }

    function bytesToB64url(input) {
      if (input === null || input === undefined) return null;
      const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      let binary = "";
      for (const b of bytes) binary += String.fromCharCode(b);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function normalizeCreationOptions(options) {
      const normalized = JSON.parse(JSON.stringify(options));
      normalized.challenge = b64urlToBytes(normalized.challenge);
      if (normalized.user && normalized.user.id) {
        normalized.user.id = b64urlToBytes(normalized.user.id);
      }
      if (Array.isArray(normalized.excludeCredentials)) {
        normalized.excludeCredentials = normalized.excludeCredentials.map((credential) => ({
          ...credential,
          id: b64urlToBytes(credential.id),
        }));
      }
      return normalized;
    }

    function normalizeRequestOptions(options) {
      const normalized = JSON.parse(JSON.stringify(options));
      normalized.challenge = b64urlToBytes(normalized.challenge);
      if (Array.isArray(normalized.allowCredentials)) {
        normalized.allowCredentials = normalized.allowCredentials.map((credential) => ({
          ...credential,
          id: b64urlToBytes(credential.id),
        }));
      }
      return normalized;
    }

    function normalizeClientExtensions(result) {
      if (!result || typeof result !== "object") return undefined;
      const output = {};
      for (const [key, value] of Object.entries(result)) {
        if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
          output[key] = bytesToB64url(value);
          continue;
        }
        if (value && typeof value === "object") {
          output[key] = normalizeClientExtensions(value);
          continue;
        }
        output[key] = value;
      }
      return output;
    }

    function registrationPayload(credential) {
      return {
        id: credential.id,
        rawId: bytesToB64url(credential.rawId),
        type: credential.type || "public-key",
        response: {
          clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
          attestationObject: bytesToB64url(credential.response.attestationObject),
        },
        clientExtensionResults: normalizeClientExtensions(credential.getClientExtensionResults?.()),
      };
    }

    function authenticationPayload(credential) {
      return {
        id: credential.id,
        rawId: bytesToB64url(credential.rawId),
        type: credential.type || "public-key",
        response: {
          clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
          authenticatorData: bytesToB64url(credential.response.authenticatorData),
          signature: bytesToB64url(credential.response.signature),
          userHandle: bytesToB64url(credential.response.userHandle),
        },
        clientExtensionResults: normalizeClientExtensions(credential.getClientExtensionResults?.()),
      };
    }

    async function postCompletion(payload) {
      await fetch(callbackBase + "/complete?token=" + encodeURIComponent(token), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    }

    function closeWindowIfPossible(messagePrefix) {
      setStatus(messagePrefix + " response sent to CLI. Closing this tab...");
      setTimeout(() => {
        try {
          window.close();
        } catch (_) {}
        if (!window.closed) {
          try {
            window.open("", "_self");
            window.close();
          } catch (_) {}
        }
        if (!window.closed) {
          setStatus(
            messagePrefix + " response sent to CLI. This browser blocked auto-close; you can close this tab.",
          );
        }
      }, 300);
    }

    async function run() {
      if (!callbackBase || !token || !command) {
        setStatus("Missing required query parameters (callback, token, command).", true);
        return;
      }
      summaryEl.textContent = "Command: " + command;
      setStatus("Requesting ceremony options from CLI...");
      try {
        const optionsResponse = await fetch(
          callbackBase + "/options?token=" + encodeURIComponent(token),
          { method: "GET" },
        );
        const optionsEnvelope = await optionsResponse.json();
        if (!optionsEnvelope.ok) {
          throw new Error(optionsEnvelope.error || "Failed to read ceremony options from CLI.");
        }

        setStatus("Prompting platform authenticator...");
        let credential;
        if (command === "register") {
          const publicKey = normalizeCreationOptions(optionsEnvelope.options);
          credential = await navigator.credentials.create({ publicKey });
          await postCompletion({ ok: true, response: registrationPayload(credential) });
          closeWindowIfPossible("Registration");
          return;
        }
        if (command === "authenticate") {
          const publicKey = normalizeRequestOptions(optionsEnvelope.options);
          credential = await navigator.credentials.get({ publicKey });
          await postCompletion({ ok: true, response: authenticationPayload(credential) });
          closeWindowIfPossible("Authentication");
          return;
        }
        throw new Error("Unsupported command '" + command + "'.");
      } catch (error) {
        const message = error?.message || String(error);
        await postCompletion({ ok: false, error: message });
        setStatus(message, true);
      }
    }

    run();
  </script>
</body>
</html>
"""
