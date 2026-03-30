# Compose Passkey Readiness Checklist

Use this checklist before declaring the sample ready.

## 1. Build and automated checks

Run:

```bash
./gradlew :samples:compose-passkey:allTests \
  :samples:compose-passkey:compileAndroidMain \
  :samples:compose-passkey:compileKotlinIosSimulatorArm64 \
  :samples:compose-passkey-android:compileDebugAndroidTestKotlin \
  :samples:compose-passkey-android:lintDebug \
  :samples:compose-passkey-android:assembleDebug --stacktrace
```

Pass condition:

- all commands succeed without test failures.
- shared sample tests cover sealed-state lifecycle outcomes for register/sign-in plus debug-log transition behavior.
- runtime platform client wiring is provided by `webauthn-client-compose` (`rememberPasskeyClient()` + `rememberPasskeyController()`).
- Android UI smoke test sources compile in CI (`:samples:compose-passkey-android:compileDebugAndroidTestKotlin`).

## 2. Local sample backend

Run:

```bash
./gradlew :samples:backend-ktor:run
```

or for ngrok-based physical-device runs:

```bash
./samples/backend-ktor/start-server.sh
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

Run:

```bash
./gradlew :samples:compose-passkey-android:installDebug
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

```bash
adb logcat -d | rg "FATAL EXCEPTION|AndroidRuntime"
```

## 4. Debug trace verification

Run:

```bash
adb logcat | rg "PasskeyDemo"
```

Pass condition:

- app/action/controller/http events are present and readable.
- hidden in-app debug sheet opens only after double-tapping the `WebAuthn Kotlin Demo` title on the signed-in screen.

## 5. Optional emulator smoke run

Run (with emulator/device connected):

```bash
./gradlew :samples:compose-passkey-android:connectedDebugAndroidTest --stacktrace
```

Pass condition:

- `MainActivitySmokeTest` passes (`app_launches_without_crash`).
