# samples:compose-passkey

Compose Multiplatform sample app for a minimal passkey E2E flow against the temporary backend in `temp.server`.

## What this demonstrates

1. Runtime capability probing (`supportsPrf`, Large Blob read/write, security key support).
2. End-to-end passkey registration against `POST /register/options` + `/register/verify`.
3. End-to-end passkey sign-in against `POST /authenticate/options` + `/authenticate/verify`.
4. Sealed, Compose-native passkey lifecycle state (`Idle`, `InProgress`, `Success`, `Failure`) driving UI status and action enablement.
5. Timeline logging for lifecycle transitions (start and terminal result) plus capability bootstrap logs.
6. Structured debug logging for internal calls and network traces (sanitized).

Default endpoints:

- Android: `http://10.0.2.2:8787` (Android Emulator host loopback)
- iOS: `http://127.0.0.1:8787`

## Run (Android)

1. Start temporary backend:

```bash
cd temp.server
npm start
```

2. Build and run sample host app:

```bash
./gradlew :samples:compose-passkey-android:installDebug
```

3. Optional UI smoke test (emulator/device connected):

```bash
./gradlew :samples:compose-passkey-android:connectedDebugAndroidTest
```

## iOS integration note

This module exposes a Compose entrypoint:

- `dev.webauthn.samples.composepasskey.MainViewController()`

Use it from an external iOS app host to render the sample UI.

## Debug logging

The sample emits structured logs with tag `PasskeyDemo`:

- ceremony steps: `register.*`, `auth.*`
- network traces: `http.engine` (sanitized)

Sensitive fields are redacted (`challenge`, `clientDataJSON`, `attestationObject`, `authenticatorData`, `signature`, `rawId`, credential identifiers).

To inspect logs:

- Android: `adb logcat | grep PasskeyDemo`
- iOS: Xcode/device console output (`NSLog`)

## Test layering (fake vs real client)

- `samples:compose-passkey` `commonTest` validates flow behavior with `FakePasskeyClient` and fake backend helpers so orchestration is deterministic across KMP targets.
- Runtime client wiring uses `webauthn-client-compose` (`rememberPasskeyClient()` + `rememberPasskeyClientState()`).
- Final readiness still requires the live register/sign-in checklist run on a real/emulated Android device with provider dependencies present.

## Android provider prerequisite

The Android host includes `androidx.credentials:credentials-play-services-auth`, but real passkey prompts still require:

1. Google Play-enabled emulator/device.
2. Screen lock configured.
3. A passkey-capable account/provider on the device.

If provider wiring is missing at runtime, the sample surfaces an actionable hint in status + timeline.

## Practical passkey note

For realistic device passkey prompts, use HTTPS plus associated-domain configuration:

- Android: `/.well-known/assetlinks.json`
- iOS: `/.well-known/apple-app-site-association`

This sample intentionally uses fixed minimal config values to keep the E2E ceremony flow focused.
