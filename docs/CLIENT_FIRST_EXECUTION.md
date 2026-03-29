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

```kotlin
val serverClient = KtorPasskeyServerClient(
    httpClient = client,
    endpointBase = "https://your-host",
)
```

If your backend uses the same payload semantics but different paths, pass `KtorPasskeyRoutes(...)` to `KtorPasskeyServerClient`.

### Option B: Host-provided custom backend contract

If your backend payloads differ from the default `/webauthn/*` contract, provide your own `PasskeyServerClient` implementation instead of trying to extend `KtorPasskeyServerClient`.

## Local Backend App (`samples/backend-ktor`)

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

```bash
./gradlew :samples:backend-ktor:run
```

Run with ngrok + local.properties synchronization:

```bash
./samples/backend-ktor/start-server.sh
```

Defaults:

- `PORT=8080`
- `WEBAUTHN_SAMPLE_ATTESTATION=STRICT` (set `NONE` to explicitly relax attestation checks for local bring-up)
- `ANDROID_PACKAGE_NAME=dev.webauthn.samples.composepasskey.android`
- `ANDROID_SHA256=PUT_SHA256_FINGERPRINT_HERE` (replace for real-device app-link verification)
- `IOS_APP_ID=TEAMID.com.example.app`
- Optional convenience inputs: `IOS_TEAM_ID`, `IOS_BUNDLE_ID` (used to derive `IOS_APP_ID` when unset)

The helper script writes `WEBAUTHN_DEMO_ENDPOINT`, `WEBAUTHN_DEMO_RP_ID`, and `WEBAUTHN_DEMO_ORIGIN` to root `local.properties`.

Use the committed iOS host app sample (`samples/compose-passkey-ios`) for device/simulator runs.
The shared Compose module still exposes `MainViewController()` for custom host integration.

## Client Dependencies Required

### `webauthn-client-core`

- `:webauthn-model`
- `at.asitplus:kmmresult`
- `kotlinx-coroutines-core`
- Typed-only ceremony API surface (no JSON codec requirement)

### `webauthn-client-json-core` (optional)

- `:webauthn-client-core`
- `:webauthn-serialization-kotlinx`
- `kotlinx-serialization-json`
- Provides `JsonPasskeyClient`, `PasskeyJsonMapper`, and `KotlinxPasskeyJsonMapper`

JSON interop wrapper example for a typed client:

```kotlin
import dev.webauthn.client.withJsonSupport
import dev.webauthn.client.android.AndroidPasskeyClient

val typedClient = AndroidPasskeyClient(context)
val jsonClient = typedClient.withJsonSupport()
```

### `webauthn-client-android`

- `:webauthn-client-core`
- `:webauthn-client-json-core`
- `androidx.credentials`
- `androidx.credentials:credentials-play-services-auth` (required for Google Play provider integration on Android)
- `androidx.core:core-ktx`

### `webauthn-client-ios`

- `:webauthn-client-core`
- `:webauthn-client-json-core`
- `kotlinx-coroutines-core`

### `webauthn-client-compose` (optional)

- `:webauthn-client-core`
- `org.jetbrains.compose.runtime:runtime`
- Android actual: `:webauthn-client-android`
- iOS actual: `:webauthn-client-ios`

## Association File Requirement

Passkey platform APIs require associated-domain files for realistic end-to-end testing.

- Android: `https://<host>/.well-known/assetlinks.json`
- iOS: `https://<host>/.well-known/apple-app-site-association`

`samples/backend-ktor` serves both endpoints for local/ngrok workflows.
