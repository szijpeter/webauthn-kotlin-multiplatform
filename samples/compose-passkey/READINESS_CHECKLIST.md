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

## 2. Local temp server

Run:

```bash
cd temp.server
npm start
```

or for ngrok-based physical device runs:

```bash
./temp.server/start-server.sh
```

Pass condition:

- server starts on `http://127.0.0.1:8787`.

## 3. Android manual flow (required)

Prerequisites:

- Google Play-enabled emulator/device
- screen lock configured
- internet access to temp server host
- build-time endpoint configured via `WEBAUTHN_DEMO_ENDPOINT` for your target
  - emulator: `http://10.0.2.2:8787`
  - physical device: `http://<laptop-lan-ip>:8787`

Run:

```bash
./gradlew :samples:compose-passkey-android:installDebug
adb shell am start -n dev.webauthn.samples.composepasskey.android/.MainActivity
```

Pass criteria:

1. App launch succeeds.
2. `Register` succeeds and debug log records registration success.
3. `Sign In` succeeds and debug log records authentication success.
4. No fatal crash in logcat while running the flow.

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

## 5. Optional emulator smoke run

Run (with emulator/device connected):

```bash
./gradlew :samples:compose-passkey-android:connectedDebugAndroidTest --stacktrace
```

Pass condition:

- `MainActivitySmokeTest` passes (`app_launches_without_crash`).
