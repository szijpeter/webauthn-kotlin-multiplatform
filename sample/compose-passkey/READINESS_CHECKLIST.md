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
- runtime platform client wiring is provided by `webauthn-client-compose` (`rememberPasskeyClient()` + `rememberPasskeyController()`), and the auth route remains the clearest reference usage.
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

## 4. Debug trace verification

Run:

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-6; owner=markdown; verify=syntax; audience=consumer -->
```bash
adb logcat | rg "PasskeyDemo"
```

Pass condition:

- app/action/controller/http events are present and readable.
- in-app debug sheet opens from the explicit `Logs` header action on both screens.

## 5. Optional emulator smoke run

Run (with emulator/device connected):

<!-- doc-example: id=sample-compose-passkey-readiness-checklist-bash-7; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:compose-passkey-android:connectedDebugAndroidTest --stacktrace
```

Pass condition:

- `MainActivitySmokeTest` passes (`app_launches_without_crash`).
