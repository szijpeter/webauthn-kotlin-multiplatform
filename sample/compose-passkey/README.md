# sample:compose-passkey

Compose Multiplatform sample app for a minimal passkey E2E flow against `sample/backend-ktor`.

## What this demonstrates

1. Runtime capability probing via `PasskeyCapabilities.supports(...)` (PRF extension, Large Blob extension, security key support, conditional create support).
2. End-to-end passkey registration against `POST /webauthn/registration/start` + `/webauthn/registration/finish`,
   including an `Auto Create` action that exercises conditional passkey creation via `PasskeyCreateOptions.Conditional`.
3. End-to-end passkey sign-in against `POST /webauthn/authentication/start` + `/webauthn/authentication/finish`.
4. Two-screen auth/session flow: `Auth` screen (`Register`, `Sign In`) and signed-in extension demo screen with local logout transition back to `Auth`.
5. Compose-first auth wiring via `rememberPasskeyController(...)`, with `PasskeyControllerState` driving UI status and action enablement.
6. Direct sample wiring to `KtorPasskeyServerClient` against the default backend contract.
7. PRF crypto demo flow: caller-owned salt load/generation, `Sign In + PRF`, session key derivation, AES-GCM encrypt/decrypt, and explicit session clear.
8. Explicit `Logs` action in the shared header opening an in-app debug log sheet (wall-clock timestamps, level, source, message).
9. Structured ceremony + network logs emitted with tag `PasskeyDemo`.
10. Android Restore Credentials demo card: create a restore key with the normal registration options, test retrieval through the normal sign-in finish path, and clear the restore key during local sign-out.
11. Android Credential Manager signal demo: after successful sign-in, the sample sends a current-user-details signal and logs whether Credential Manager accepted it.

Build-time config is shared across Android and iOS (not platform-specific). These env vars are baked into the app during build:

- `WEBAUTHN_DEMO_ENDPOINT` (default: `http://127.0.0.1:8080`)
- `WEBAUTHN_DEMO_RP_ID` (default: `localhost`)
- `WEBAUTHN_DEMO_ORIGIN` (default: `https://localhost`)
- `WEBAUTHN_DEMO_USER_ID` (default: `demo-user-1`)
- `WEBAUTHN_DEMO_USER_NAME` (default: `demo@local`)
- Android host only: `WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION` (default: `false`)

Examples:

- Android Emulator host alias: `WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080`
- Physical phone on LAN: `WEBAUTHN_DEMO_ENDPOINT=http://<laptop-lan-ip>:8080`
- ngrok tunnel: `WEBAUTHN_DEMO_ENDPOINT=https://<domain>` and set `WEBAUTHN_DEMO_RP_ID/WEBAUTHN_DEMO_ORIGIN` to the same HTTPS domain

## Run (Android)

Android requirement: API level 30+ (`minSdk 30`) for the PRF crypto sample flow.

1. Start sample backend:

```bash
./gradlew :sample:backend-ktor:run
```

For physical devices, prefer tunnel mode:

```bash
./sample/backend-ktor/start-server.sh
```

This updates root `local.properties` (`WEBAUTHN_DEMO_ENDPOINT`, `WEBAUTHN_DEMO_RP_ID`, `WEBAUTHN_DEMO_ORIGIN`) to match the active ngrok domain.

Android 17 note: the Android host targets SDK 37, so direct private-network endpoints
such as `10.0.2.2`, `192.168.x.x`, or `172.16-31.x.x` require the platform
`ACCESS_LOCAL_NETWORK` runtime permission. Set
`WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION=true` when building the sample
against one of those direct local endpoints. Public HTTPS endpoints and loopback
defaults do not need the prompt.

2. Build and run sample host app:

```bash
WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080 \
WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION=true \
./gradlew :sample:compose-passkey-android:installDebug
```

The `Auto Create` button on the auth screen uses the conditional-create path. It is meant for
manual platform smoke testing after confirming the capabilities card advertises `Auto Create`.
On Android, seeing `No credential creation option found` is a valid conditional-create outcome
when no enabled credential provider can silently create a passkey; explicit registration remains
the `Register` button path.

3. Optional UI smoke test (emulator/device connected):

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
- `action`: register/sign-in taps
- `prf`: PRF sign-in/session/encrypt/decrypt outcomes
- `signals`: Android Credential Manager signal outcomes
- `controller`: state transitions (`STARTING`, `PLATFORM_PROMPT`, `FINISHING`, terminal outcomes)
- `http`: raw Ktor engine lines

To inspect logs:

- Android: `adb logcat | grep PasskeyDemo`
- iOS: Xcode/device console output (`NSLog`)
- In-app: tap `Logs` in the header on either screen to open the debug sheet.

## Auth route showcase

The auth screen is intentionally the cleanest API example in the repo:

```kotlin
val controller = rememberPasskeyController(
    serverClient = serverClient,
    passkeyClient = passkeyClient,
)
val controllerState by controller.uiState.collectAsState()

AuthScreen(
    status = controllerState.toDemoStatus(),
    actionsEnabled = areCeremonyActionsEnabled(controllerState),
    canRegister = authState.canRegister,
    runtimeHint = authState.runtimeHint,
    onShowLogs = showDebugLogs,
    onRegister = { scope.launch { controller.register(config.toRegistrationStartPayload()) } },
    onSignIn = { scope.launch { controller.signIn(config.toAuthenticationStartPayload()) } },
)
```

Sample-only side effects stay outside the library API surface:

- `AuthDemoCoordinator` logs taps/state transitions.
- `AuthDemoCoordinator` sends the platform current-user-details signal after successful sign-in when the platform client is available.
- `AppSessionStore` handles local signed-in navigation state.

## Android Restore Credentials showcase

The signed-in demo screen includes an Android-only Restore Credentials card. It uses the published
`webauthn-client-android` restore client directly from the sample app so the platform API added by
the Android module is exercised by a visible flow, not only by unit tests.

The flow intentionally mirrors Android's recommended lifecycle:

- `Create` requests registration options from `sample/backend-ktor`, creates an Android restore key, and sends the registration response back through the same server finish path used by passkeys.
- `Test` requests authentication options, asks Credential Manager for the restore credential, and sends the assertion back through the same sign-in finish path used by passkeys.
- `Clear Restore Key` calls the platform clear operation, and local logout also clears the restore key when the Android client is available.

This card is a development harness for the create/get/clear API shape. A true device-transfer
validation still needs Android backup/restore or first-launch testing on a restored device. iOS shows
the card as unavailable because Apple passkeys sync through iCloud Keychain, but AuthenticationServices
does not expose an app-managed Restore Credentials equivalent.

## Credential signal showcase

After successful sign-in, the sample can send a current-user-details signal to the platform
credential manager and log whether the platform accepted it. This is a sample-side integration over
the Android-only `AndroidCredentialSignalClient`; it does not replace server-side credential-state
enforcement.

The sample only exercises `SignalCurrentUserDetailsRequest` because it already has the RP ID, stable
user handle, and display name during sign-in. `SignalAllAcceptedCredentialIdsRequest` and
`SignalUnknownCredentialRequest` require a real server-side credential inventory or an unknown
credential failure path, so those stay in the Android module API and docs until the sample backend
exposes that state.

On iOS, Apple exposes the analogous `ASCredentialDataManager` sync reports from Swift, but the
current Kotlin/Native SDK bindings do not expose that Swift-only type under
`platform.AuthenticationServices`. The committed iOS host app therefore injects a tiny Swift
`IosCredentialSignalBridge` implementation into `MainViewController(...)`; Kotlin owns the sample
flow, while Swift owns the iOS 26.2+ AuthenticationServices call.

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

- `sample:compose-passkey` `commonTest` validates flow behavior with `FakePasskeyClient` and `FakeServerClient` (`PasskeyServerClient`) so orchestration is deterministic across KMP targets.
- Runtime client wiring uses `webauthn-client-compose` (`rememberPasskeyClient()` + `rememberPasskeyController()`).
- Runtime server wiring uses `webauthn-network-ktor-client` (`KtorPasskeyServerClient`).
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
