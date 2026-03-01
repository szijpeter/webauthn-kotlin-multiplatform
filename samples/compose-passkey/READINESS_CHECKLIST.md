# Compose Passkey Readiness Checklist

Use this checklist before declaring the sample ready.

## 1. Build and automated checks

Run:

```bash
./gradlew :samples:compose-passkey:allTests \
  :samples:compose-passkey:compileAndroidMain \
  :samples:compose-passkey:compileKotlinIosSimulatorArm64 \
  :webauthn-client-android:testDebugUnitTest \
  :samples:compose-passkey-android:compileDebugAndroidTestKotlin \
  :samples:compose-passkey-android:lintDebug \
  :samples:compose-passkey-android:assembleDebug --stacktrace
```

Pass condition:

- all commands succeed without test failures.
- shared sample integration tests may use a fake platform bridge for determinism, but real Android passkey client behavior is covered by `:webauthn-client-android:testDebugUnitTest` in the same gate.
- deterministic health action orchestration is covered by `PasskeyDemoControllerTest.health_check_success_updates_status_and_logs` in `:samples:compose-passkey:allTests`.
- Android UI smoke test sources compile in CI (`:samples:compose-passkey-android:compileDebugAndroidTestKotlin`).

## 2. Local temp server

Run:

```bash
cd temp.server
npm start
```

Pass condition:

- server starts on `http://127.0.0.1:8787`.

## 3. Android manual flow (required)

Prerequisites:

- Google Play-enabled emulator/device
- screen lock configured
- internet access to temp server host (default emulator host alias is `10.0.2.2`)

Run:

```bash
./gradlew :samples:compose-passkey-android:installDebug
adb shell am start -n dev.webauthn.samples.composepasskey.android/.MainActivity
```

Pass criteria:

1. App launch succeeds.
2. `Check Health` succeeds.
3. `Register` succeeds and timeline records registration success.
4. `Sign In` succeeds and timeline records authentication success.
5. No fatal crash in logcat while running the flow.

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

- action and network events are present.
- sensitive fields are redacted in log lines.

## 5. Optional emulator smoke run

Run (with emulator/device connected):

```bash
./gradlew :samples:compose-passkey-android:connectedDebugAndroidTest --stacktrace
```

Pass condition:

- `MainActivitySmokeTest` passes (`app_launches_without_crash`).
