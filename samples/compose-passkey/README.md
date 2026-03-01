# samples:compose-passkey

Compose Multiplatform sample app for client-readiness verification against the temporary backend in `temp.server`.

## What this demonstrates

1. Runtime capability probing (`supportsPrf`, Large Blob read/write, security key support).
2. End-to-end passkey registration against `POST /register/options` + `/register/verify`.
3. End-to-end passkey sign-in against `POST /authenticate/options` + `/authenticate/verify`.
4. Editable endpoint and identity fields for local and tunneled development hosts.
5. Timeline logs with operation status, categorized errors, and actionable hints.
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

- internal actions: `action.start`, `action.success`, `action.failure`
- ceremony steps: `register.*`, `auth.*`, `health.*`
- network traces: `http.engine` (sanitized)

Sensitive fields are redacted (`challenge`, `clientDataJSON`, `attestationObject`, `authenticatorData`, `signature`, `rawId`, credential identifiers).

To inspect logs:

- Android: `adb logcat | grep PasskeyDemo`
- iOS: Xcode/device console output (`NSLog`)

## Test layering (fake vs real client)

- `samples:compose-passkey` `commonTest` uses a `FakePasskeyClient` only at the platform bridge boundary so orchestration and mapping tests stay deterministic across KMP targets.
- Real Android platform behavior is verified in `:webauthn-client-android:testDebugUnitTest` (the actual `AndroidPasskeyClient` path), and this task is required by changed-scope quality gates for the compose sample.
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

The in-app `endpointBase` field can target ngrok or another HTTPS tunnel when needed.
