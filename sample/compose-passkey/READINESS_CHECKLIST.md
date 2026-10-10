# Compose Passkey Readiness Checklist

Use this checklist before declaring the sample ready.

## 1. Build and automated checks

Run:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-1; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:compose-passkey:allTests \
  :sample:compose-passkey:compileAndroidMain \
  :sample:compose-passkey:compileKotlinIosSimulatorArm64 \
  :sample:compose-passkey-android:compileDebugAndroidTestKotlin \
  :sample:compose-passkey-android:lintDebug \
  :sample:compose-passkey-android:assembleDebug --stacktrace
```

Pass condition:

- all commands succeed without test failures.
- shared sample tests cover sealed-state lifecycle outcomes for register/sign-in plus debug-log transition behavior.
- runtime platform client wiring is provided by `webauthn-client-compose` (`rememberPasskeyClient()` + `rememberPasskeyFlow()`), and the auth route remains the clearest reference usage.
- Android UI smoke test sources compile in CI (`:sample:compose-passkey-android:compileDebugAndroidTestKotlin`).

## 2. Local sample backend

Run:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-2; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:backend-ktor:run
```

or for ngrok-based physical-device runs:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-3; owner=markdown; verify=syntax; audience=consumer -->
```bash
./sample/backend-ktor/start-server.sh
```

Pass condition:

- server starts on `http://127.0.0.1:8080`.
- `GET /health` returns `{ "status": "ok" }`.

## 3. Android manual flow (required)

Prerequisites:

- Google Play-enabled emulator/device
- screen lock configured
- internet access to sample backend host
- build-time endpoint configured via `WEBAUTHN_DEMO_ENDPOINT` for your target
  - emulator: `http://10.0.2.2:8080`
  - physical device: `http://<laptop-lan-ip>:8080`
- backend `ANDROID_SHA256` association matches the certificate that signs the
  installed app; the Android host derives the matching ceremony origin at runtime
- Android 17 / target SDK 37 local-network permission granted when using a
  private-network endpoint from an emulator or physical device; build with
  `WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION=true`

Run:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-4; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:compose-passkey-android:installDebug
adb shell am start -n dev.webauthn.samples.composepasskey.android/.MainActivity
```

Pass criteria:

1. App launch succeeds.
2. `Auth` screen is shown first with both `Register` and `Sign In` actions.
3. `Register` succeeds and debug log records registration success.
4. `Sign In` succeeds, transitions to the signed-in demo screen, and debug log records authentication success.
5. `Local Logout` returns to `Auth` and clears active local session state.
6. No fatal crash in logcat while running the flow.

Suggested crash check:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-5; owner=markdown; verify=syntax; audience=consumer -->
```bash
adb logcat -d | rg "FATAL EXCEPTION|AndroidRuntime"
```

## 4. Android restore credential manual flow (required when restore card changes)

Prerequisites:

- Android 9+ device/emulator with Google Play services core 24220000+ and Credential Manager
  restore support (`androidx.credentials` 1.5+; this repository uses 1.6).
- Existing signed-in session from the Android manual flow.
- Sample backend reachable with the same `WEBAUTHN_DEMO_*` configuration used for passkey register/sign-in.

Pass criteria:

1. Signed-in demo screen shows the `Restore Credentials` card.
2. `Create` completes and status reports that the restore key was verified by the server.
3. `Test` completes and status reports that restore credential sign-in was verified.
4. `Clear Restore Key` completes without leaving the screen.
5. `Local Logout` clears the restore key when the platform client is available and returns to `Auth`.
6. A full restore-device claim is not made unless the flow is also exercised through Android backup/restore or first launch on a restored device.

## 5. Debug trace verification

Run:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-6; owner=markdown; verify=syntax; audience=consumer -->
```bash
adb logcat | rg "PasskeyDemo"
```

Pass condition:

- app/action/flow/http events are present and readable.
- HTTP entries contain request/response metadata without bodies under the default
  configuration.
- on Android, successful sign-in logs a `signals` entry when Credential Manager accepts or rejects the current-user-details signal.
- in-app debug sheet opens from the explicit `Logs` header action on both screens.

For an isolated debugging session, build with
`WEBAUTHN_DEMO_UNSAFE_HTTP_BODY_LOGGING=true` to include raw HTTP bodies. This
explicit escape hatch does not redact WebAuthn or PRF material; never use its logs
as shareable test evidence.

## 6. Optional emulator smoke run

Run (with emulator/device connected):

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-7; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:compose-passkey-android:connectedDebugAndroidTest --stacktrace
```

Pass condition:

- `MainActivitySmokeTest` passes (`app_launches_without_crash`).
