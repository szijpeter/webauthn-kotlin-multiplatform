# sample:compose-passkey

Compose Multiplatform sample app for a minimal passkey E2E flow against `sample/backend-ktor`.

## What this demonstrates

1. Runtime capability probing via `PasskeyCapabilities.supports(...)` (PRF extension, Large Blob extension, security key support, conditional create support).
2. End-to-end passkey registration against `POST /webauthn/registration/start` + `/webauthn/registration/finish`, including an `Auto Create` action that passes `PasskeyCreateOptions.Conditional` through `PasskeyFlow`.
3. End-to-end passkey sign-in against `POST /webauthn/authentication/start` + `/webauthn/authentication/finish`.
4. Two-screen auth/session flow: `Auth` screen (`Register`, `Sign In`) and signed-in extension demo screen with local logout transition back to `Auth`.
5. Compose-first auth wiring via `rememberPasskeyFlow(...)`, with sample-owned state and errors driving UI status and action enablement.
6. Direct sample wiring to `KotlinxKtorPasskeyBackend` against the default backend contract.
7. PRF crypto demo flow: caller-owned salt load/generation, `Sign In + PRF`, session key derivation, AES-GCM encrypt/decrypt, and explicit session clear.
8. Explicit `Logs` action in the shared header opening an in-app debug log sheet (wall-clock timestamps, level, source, message).
9. Structured ceremony + network logs emitted with tag `PasskeyDemo`.

These values are baked into the shared app during build:

- `WEBAUTHN_DEMO_ENDPOINT` (default: `http://127.0.0.1:8080`)
- `WEBAUTHN_DEMO_RP_ID` (default: `localhost`)
- `WEBAUTHN_DEMO_ORIGIN` (iOS/web origin; default: `https://localhost`)
- `WEBAUTHN_DEMO_USER_ID` (default: `demo-user-1`)
- `WEBAUTHN_DEMO_USER_NAME` (default: `demo@local`)
- `WEBAUTHN_DEMO_UNSAFE_HTTP_BODY_LOGGING` (default: `false`)
- Android host only: `WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION` (default: `false`)

The Android host does not use `WEBAUTHN_DEMO_ORIGIN`. Credential Manager sets an
Android app origin from the SHA-256 fingerprint of the installed app's signing
certificate, so the host derives the matching `android:apk-key-hash:...` value at
runtime and injects it into the shared sample.

Examples:

- Android Emulator host alias: `WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080`
- Physical phone on LAN: `WEBAUTHN_DEMO_ENDPOINT=http://<laptop-lan-ip>:8080`
- ngrok tunnel: `WEBAUTHN_DEMO_ENDPOINT=https://<domain>` and set `WEBAUTHN_DEMO_RP_ID/WEBAUTHN_DEMO_ORIGIN` to the same HTTPS domain for the iOS/web association; Android derives its app origin from its signing certificate

## Run (Android)

Android requirement: API level 30+ (`minSdk 30`) for the PRF crypto sample flow.

1. Start sample backend:

<!-- doc-example: id=sample-compose-passkey-readme-bash-1; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:backend-ktor:run
```

For physical devices, prefer tunnel mode:

<!-- doc-example: id=sample-compose-passkey-readme-bash-2; owner=markdown; verify=syntax; audience=consumer -->
```bash
./sample/backend-ktor/start-server.sh
```

This updates root `local.properties` (`WEBAUTHN_DEMO_ENDPOINT`,
`WEBAUTHN_DEMO_RP_ID`, `WEBAUTHN_DEMO_ORIGIN`) to match the active ngrok domain.
It also synchronizes the Android signing fingerprint used by Digital Asset Links;
the Android app derives its ceremony origin from the installed signing certificate.

Android 17 note: the Android host targets SDK 37, so direct private-network endpoints
such as `10.0.2.2`, `192.168.x.x`, or `172.16-31.x.x` require the platform
`ACCESS_LOCAL_NETWORK` runtime permission. Set
`WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION=true` when building the sample
against one of those direct local endpoints. Public HTTPS endpoints and loopback
defaults do not need the prompt.

2. Build and run sample host app:

<!-- doc-example: id=sample-compose-passkey-readme-bash-3; owner=markdown; verify=syntax; audience=consumer -->
```bash
WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080 \
WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION=true \
./gradlew :sample:compose-passkey-android:installDebug
```

The `Auto Create` button is for conditional-create smoke testing after confirming the capabilities
card advertises it. On Android, a “No credential creation option is available” result is valid when
no enabled provider can create a passkey opportunistically. The `Register` button remains the
explicit registration path.

3. Optional UI smoke test (emulator/device connected):

<!-- doc-example: id=sample-compose-passkey-readme-bash-4; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:compose-passkey-android:connectedDebugAndroidTest
```

## Run (iOS host app)

Use the committed iOS host project:

- [`sample/compose-passkey-ios`](../compose-passkey-ios/README.md)

Quick start:

1. Open `sample/compose-passkey-ios/ComposePasskeyIos.xcodeproj` in Xcode.
2. Set your signing team and a unique bundle id.
3. Connect your iPhone and run.

This shared module still exports the Compose entrypoint used by the host app:

- `dev.webauthn.samples.composepasskey.MainViewController()`

Free-account expectation:

- App install/launch is supported.
- Real passkey register/sign-in may fail when Associated Domains entitlement/domain association is unavailable.

Full E2E expectation:

- Use HTTPS domain + Associated Domains + matching `IOS_APP_ID`/bundle identity.
- `sample/backend-ktor/start-server.sh` (ngrok helper) remains the default physical-device setup path.

## Debug logging

The sample emits structured logs with tag `PasskeyDemo` and uses the same entries for the in-app debug sheet:

- `app`: startup and configuration
- `capabilities`: probe start/success/failure
- `action`: register/auto-create/sign-in taps
- `prf`: PRF sign-in/session/encrypt/decrypt outcomes
- `flow`: state transitions (`STARTING`, `PLATFORM_PROMPT`, `FINISHING`, terminal outcomes)
- `http`: Ktor request/response metadata (method, URL, and status)

HTTP bodies are excluded by default because WebAuthn responses and PRF extension
values contain sensitive material. For an explicit local debugging session, build
with `WEBAUTHN_DEMO_UNSAFE_HTTP_BODY_LOGGING=true` to switch the Ktor logger to
`LogLevel.BODY`. This escape hatch performs no redaction; disable it before sharing
logs or distributing a build.

To inspect logs:

- Android: `adb logcat | grep PasskeyDemo`
- iOS: Xcode/device console output (`NSLog`)
- In-app: tap `Logs` in the header on either screen to open the debug sheet.

## Auth route showcase

The auth screen is intentionally the cleanest API example in the repo:

<!-- doc-example: id=sample-compose-passkey-readme-kotlin-1; owner=sample; verify=sample-build; audience=consumer; source=sample/compose-passkey/src/commonMain/kotlin/dev/webauthn/samples/composepasskey/ui/screens/auth/AuthRoute.kt#compose-sample-auth-route -->
```kotlin
    val flow = rememberPasskeyFlow(passkeyClient)
    val scope = rememberCoroutineScope()
    val coordinator = remember(config, debugLogs, sessionStore) {
        AuthDemoCoordinator(config, debugLogs, sessionStore)
    }
    var state by remember { mutableStateOf<DemoCeremonyState>(DemoCeremonyState.Idle) }
    val canRegister by coordinator.canRegister.collectAsState()
    val actionsEnabled = areCeremonyActionsEnabled(state)
```

Sample-only side effects stay outside the library API surface:

- `AuthDemoCoordinator` logs taps/state transitions.
- `AppSessionStore` handles local signed-in navigation state.

## Compose previews

Preview catalog composables live in common source:

- `src/commonMain/kotlin/dev/webauthn/samples/composepasskey/ui/previews/ScreenPreviewCatalog.kt`
- `src/commonMain/kotlin/dev/webauthn/samples/composepasskey/ui/previews/ComponentPreviewCatalog.kt`

Preview limitations and constraints:

1. Previews are static and fake-state only; they must stay free of DI (`koin*`), network clients, and platform runtime calls.
2. Interactive runtime flows (Navigation 3 back stack, passkey platform prompts, live bottom-sheet gestures) are not fully represented in preview mode.
3. Android Studio rendering still relies on Android target preview tooling, so `androidMain` includes `compose.ui.tooling` for this module.
4. Treat previews as UI contract checks, not behavioral verification; lifecycle/interop behavior must still be validated via tests and host-app runs.

## Test layering (fake vs real client)

- Generic flow behavior is covered in `webauthn-client-flow`; the sample owns its presentation/error union.
- Runtime client wiring uses `webauthn-client-compose` (`rememberPasskeyClient()` + `rememberPasskeyFlow()`).
- Runtime server wiring uses `webauthn-client-ktor-kotlinx` (`KotlinxKtorPasskeyBackend`).
- Final readiness still requires the live register/sign-in checklist run on a real/emulated Android device with provider dependencies present.

## Android provider prerequisite

The Android host includes `androidx.credentials:credentials-play-services-auth`, but real passkey prompts still require:

1. Google Play-enabled emulator/device.
2. Screen lock configured.
3. A passkey-capable account/provider on the device.

If provider wiring is missing at runtime, the sample surfaces an actionable hint in status + debug log.

## Practical passkey note

For realistic device passkey prompts, use HTTPS plus associated-domain configuration:

- Android: `/.well-known/assetlinks.json`
- iOS: `/.well-known/apple-app-site-association`

`sample/backend-ktor` serves both endpoints.

## PRF crypto safety note

- Salt persistence is intentionally caller-owned and sample-local (`InMemoryPrfSaltStore`) to keep library storage-independent.
- Encrypted payloads are tied to passkey PRF output. If the passkey credential is removed, previously encrypted data cannot be recovered.
