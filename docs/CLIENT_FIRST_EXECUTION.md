# Client-First Execution

Date: 2026-03-05

Goal: keep Android and iOS client implementation moving with an in-repo backend that matches the default contract.

## Principle

1. Client work must not block on server hardening.
2. Use explicit backend contracts for interop testing.
3. Keep shared ceremony logic in `webauthn-client-core`; platform modules only bridge OS APIs.

## Backend Options for Client Bring-Up

### Option A: First-party default backend contract

Use `KtorPasskeyServerClient` with its default routes and call:

- `POST /webauthn/registration/start`
- `POST /webauthn/registration/finish`
- `POST /webauthn/authentication/start`
- `POST /webauthn/authentication/finish`

Example:

<!-- doc-example: id=docs-client-first-execution-kotlin-1; owner=source; verify=consumer-compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/NetworkClientExample.kt#network-client -->
```kotlin
import dev.webauthn.network.KtorPasskeyServerClient
import io.ktor.client.HttpClient

fun serverClient(httpClient: HttpClient): KtorPasskeyServerClient {
    return KtorPasskeyServerClient(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
}
```

If your backend uses the same payload semantics but different paths, pass `KtorPasskeyRoutes(...)` to `KtorPasskeyServerClient`.

### Option B: Host-provided custom backend contract

If your backend payloads differ from the default `/webauthn/*` contract, provide your own `PasskeyServerClient` implementation instead of trying to extend `KtorPasskeyServerClient`.

## Local Backend App (`sample/backend-ktor`)

Use the in-repo sample backend app for local and ngrok-based mobile runs.

Implemented routes:

- `POST /webauthn/registration/start`
- `POST /webauthn/registration/finish`
- `POST /webauthn/authentication/start`
- `POST /webauthn/authentication/finish`
- `GET /health`
- `GET /.well-known/assetlinks.json`
- `GET /.well-known/apple-app-site-association`
- `GET /apple-app-site-association`

Run locally:

<!-- doc-example: id=docs-client-first-execution-bash-1; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:backend-ktor:run
```

Run with ngrok + local.properties synchronization:

<!-- doc-example: id=docs-client-first-execution-bash-2; owner=markdown; verify=syntax; audience=consumer -->
```bash
./sample/backend-ktor/start-server.sh
```

Defaults:

- `PORT=8080`
- `WEBAUTHN_SAMPLE_ATTESTATION=STRICT` (set `NONE` to explicitly relax attestation checks for local bring-up)
- `ANDROID_PACKAGE_NAME=dev.webauthn.samples.composepasskey.android`
- `ANDROID_SHA256=PUT_SHA256_FINGERPRINT_HERE` (replace for real-device app-link verification)
- `IOS_APP_ID=TEAMID.com.example.app`
- Optional convenience inputs: `IOS_TEAM_ID`, `IOS_BUNDLE_ID` (used to derive `IOS_APP_ID` when unset)

The helper script writes `WEBAUTHN_DEMO_ENDPOINT`, `WEBAUTHN_DEMO_RP_ID`, and `WEBAUTHN_DEMO_ORIGIN` to root `local.properties`.

Use the committed iOS host app sample (`sample/compose-passkey-ios`) for device/simulator runs.
The shared Compose module still exposes `MainViewController()` for custom host integration.

## Client Dependencies Required

### `webauthn-client-core`

- `:core:webauthn-model`
- `at.asitplus:kmmresult`
- `kotlinx-coroutines-core`
- Typed-only ceremony API surface (no JSON codec requirement)

### `webauthn-client-json-core` (optional)

- `:client:webauthn-client-core`
- `:core:webauthn-serialization-kotlinx`
- `kotlinx-serialization-json`
- Provides `JsonPasskeyClient`, `PasskeyJsonMapper`, and `KotlinxPasskeyJsonMapper`

JSON interop wrapper example for a typed client:

<!-- doc-example: id=docs-client-first-execution-kotlin-2; owner=source; verify=platform-compile; audience=consumer; source=documentation/examples/src/androidMain/kotlin/dev/webauthn/documentation/examples/AndroidJsonClientExample.kt#android-json-client -->
```kotlin
import android.content.Context
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.client.withJsonSupport

fun androidJsonClient(context: Context): JsonPasskeyClient {
    val typedClient = AndroidPasskeyClient(context)
    return typedClient.withJsonSupport()
}
```

### `webauthn-client-android`

- `:client:webauthn-client-core`
- `:client:webauthn-client-json-core`
- `androidx.credentials`
- `androidx.credentials:credentials-play-services-auth` (required for Google Play provider integration on Android)
- `androidx.core:core-ktx`

### `webauthn-client-ios`

- `:client:webauthn-client-core`
- `:client:webauthn-client-json-core`
- `kotlinx-coroutines-core`

### `webauthn-client-compose` (optional)

- `:client:webauthn-client-core`
- `org.jetbrains.compose.runtime:runtime`
- Android actual: `:client:webauthn-client-android`
- iOS actual: `:client:webauthn-client-ios`

## Association File Requirement

Passkey platform APIs require associated-domain files for realistic end-to-end testing.

- Android: `https://<host>/.well-known/assetlinks.json`
- iOS: `https://<host>/.well-known/apple-app-site-association`

`sample/backend-ktor` serves both endpoints for local/ngrok workflows.
