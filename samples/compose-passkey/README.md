# samples:compose-passkey

Compose Multiplatform sample app for a minimal passkey E2E flow against `samples/backend-ktor`.

## What this demonstrates

1. Runtime capability probing via `PasskeyCapabilities.supports(...)` (PRF extension, Large Blob extension, security key support).
2. End-to-end passkey registration against `POST /webauthn/registration/start` + `/webauthn/registration/finish`.
3. End-to-end passkey sign-in against `POST /webauthn/authentication/start` + `/webauthn/authentication/finish`.
4. Controller-driven lifecycle state (`PasskeyControllerState`) driving UI status and action enablement.
5. Direct sample wiring to `KtorPasskeyServerClient` default backend contract.
6. PRF crypto demo flow: caller-owned salt load/generation, `Sign In + PRF`, session key derivation, AES-GCM encrypt/decrypt, and explicit session clear.
7. Single logger-backed debug log panel in UI (wall-clock timestamps, level, source, message).
8. Structured ceremony + network logs emitted with tag `PasskeyDemo`.

Build-time config is shared across Android and iOS (not platform-specific). These env vars are baked into the app during build:

- `WEBAUTHN_DEMO_ENDPOINT` (default: `http://127.0.0.1:8080`)
- `WEBAUTHN_DEMO_RP_ID` (default: `localhost`)
- `WEBAUTHN_DEMO_ORIGIN` (default: `https://localhost`)
- `WEBAUTHN_DEMO_USER_ID` (default: `demo-user-1`)
- `WEBAUTHN_DEMO_USER_NAME` (default: `demo@local`)

Examples:

- Android Emulator host alias: `WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080`
- Physical phone on LAN: `WEBAUTHN_DEMO_ENDPOINT=http://<laptop-lan-ip>:8080`
- ngrok tunnel: `WEBAUTHN_DEMO_ENDPOINT=https://<domain>` and set `WEBAUTHN_DEMO_RP_ID/WEBAUTHN_DEMO_ORIGIN` to the same HTTPS domain

## Run (Android)

Android requirement: API level 30+ (`minSdk 30`) for the PRF crypto sample flow.

1. Start sample backend:

```bash
./gradlew :samples:backend-ktor:run
```

For physical devices, prefer tunnel mode:

```bash
./samples/backend-ktor/start-server.sh
```

This updates root `local.properties` (`WEBAUTHN_DEMO_ENDPOINT`, `WEBAUTHN_DEMO_RP_ID`, `WEBAUTHN_DEMO_ORIGIN`) to match the active ngrok domain.

2. Build and run sample host app:

```bash
WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080 ./gradlew :samples:compose-passkey-android:installDebug
```

3. Optional UI smoke test (emulator/device connected):

```bash
./gradlew :samples:compose-passkey-android:connectedDebugAndroidTest
```

## Run (iOS host app)

Use the committed iOS host project:

- [`samples/compose-passkey-ios`](../compose-passkey-ios/README.md)

Quick start:

1. Open `samples/compose-passkey-ios/ComposePasskeyIos.xcodeproj` in Xcode.
2. Set your signing team and a unique bundle id.
3. Connect your iPhone and run.

This shared module still exports the Compose entrypoint used by the host app:

- `dev.webauthn.samples.composepasskey.MainViewController()`

Free-account expectation:

- App install/launch is supported.
- Real passkey register/sign-in may fail when Associated Domains entitlement/domain association is unavailable.

Full E2E expectation:

- Use HTTPS domain + Associated Domains + matching `IOS_APP_ID`/bundle identity.
- `samples/backend-ktor/start-server.sh` (ngrok helper) remains the default physical-device setup path.

## Debug logging

The sample emits structured logs with tag `PasskeyDemo` and uses the same entries for the in-app debug panel:

- `app`: startup and configuration
- `capabilities`: probe start/success/failure
- `action`: register/sign-in taps
- `prf`: PRF sign-in/session/encrypt/decrypt outcomes
- `controller`: state transitions (`STARTING`, `PLATFORM_PROMPT`, `FINISHING`, terminal outcomes)
- `http`: raw Ktor engine lines

To inspect logs:

- Android: `adb logcat | grep PasskeyDemo`
- iOS: Xcode/device console output (`NSLog`)

## Test layering (fake vs real client)

- `samples:compose-passkey` `commonTest` validates flow behavior with `FakePasskeyClient` and `FakeServerClient` (`PasskeyServerClient`) so orchestration is deterministic across KMP targets.
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

`samples/backend-ktor` serves both endpoints.

## PRF crypto safety note

- Salt persistence is intentionally caller-owned and sample-local (`InMemoryPrfSaltStore`) to keep library storage-independent.
- Encrypted payloads are tied to passkey PRF output. If the passkey credential is removed, previously encrypted data cannot be recovered.
