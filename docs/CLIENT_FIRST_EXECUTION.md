# Client-First Execution

Date: 2026-03-01

Goal: keep Android and iOS client implementation moving even when our first-party backend is not yet release-ready.

## Principle

1. Client work must not block on server hardening.
2. Use explicit backend profiles for interop testing.
3. Keep shared ceremony logic in `webauthn-client-core`; platform modules only bridge OS APIs.

## Backend Options for Client Bring-Up

### Option A: External backend profile (`PASSKEY_ENCRYPTION_POC`)

Use `KtorPasskeyServerClient` with `WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC` to call:

- `POST /register/options`
- `POST /register/verify`
- `POST /authenticate/options`
- `POST /authenticate/verify`

Example:

```kotlin
val serverClient = KtorPasskeyServerClient(
    httpClient = client,
    endpointBase = "https://your-host",
    profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
)
```

If you have the sibling repo locally, `../passkey-encryption-poc` already includes these routes and associated-domain endpoints.

### Option B: Local temporary backend (`temp.server`)

Use the local development backend in `temp.server/` when you need a fast, disposable endpoint for mobile client iteration.

- No production guarantees
- In-memory state only
- Returns WebAuthn-shaped JSON for registration/authentication
- Serves association files at `/.well-known/assetlinks.json` and `/.well-known/apple-app-site-association`

Quick demo (transport + interop profile round-trip):

```bash
cd temp.server && npm start
# in another shell
./gradlew :samples:client-interop-jvm:run
```

UI demo (Compose KMP readiness flow):

```bash
cd temp.server && npm start
# in another shell
./gradlew :samples:compose-passkey-android:installDebug
```

The shared Compose module also exposes `MainViewController()` for iOS host integration.
The Compose sample includes structured debug logging (`PasskeyDemo` tag), sanitized network traces, and a readiness runbook at `samples/compose-passkey/READINESS_CHECKLIST.md`.

### Option C: First-party backend routes

Use `WebAuthnBackendProfile.LIBRARY_ROUTES` with our in-repo server route contract when those paths are ready for your integration target.

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

Passkey platform APIs still require domain association for realistic end-to-end testing.

- Android: `https://<host>/.well-known/assetlinks.json`
- iOS: `https://<host>/.well-known/apple-app-site-association`

The `temp.server` backend exposes both endpoints for local/ngrok workflows.
