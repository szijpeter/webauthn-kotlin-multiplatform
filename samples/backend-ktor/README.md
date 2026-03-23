# samples:backend-ktor

Ktor sample backend for local/mobile passkey end-to-end flows.

## Routes

- `POST /webauthn/registration/start`
- `POST /webauthn/registration/finish`
- `POST /webauthn/authentication/start`
- `POST /webauthn/authentication/finish`
- `GET /health`
- `GET /.well-known/assetlinks.json`
- `GET /.well-known/apple-app-site-association`
- `GET /apple-app-site-association`

## Run

```bash
./gradlew :samples:backend-ktor:run
```

Environment variables:

- `PORT` (default `8080`)
- `WEBAUTHN_SAMPLE_ATTESTATION` (`STRICT` default, set `NONE` to explicitly disable strict attestation verification for local bring-up)
- `ANDROID_PACKAGE_NAME` (default `dev.webauthn.samples.composepasskey.android`)
- `ANDROID_SHA256` (default placeholder; set for real-device app-link verification)
- `IOS_APP_ID` (canonical iOS app id for AASA `webcredentials.apps`, default placeholder)
- `IOS_TEAM_ID` (optional helper input, used to derive `IOS_APP_ID` when `IOS_APP_ID` is unset)
- `IOS_BUNDLE_ID` (optional helper input, used to derive `IOS_APP_ID` when `IOS_APP_ID` is unset)

`IOS_APP_ID` resolution:

1. If `IOS_APP_ID` is set, it is used as-is.
2. Else if both `IOS_TEAM_ID` and `IOS_BUNDLE_ID` are set, backend derives `IOS_APP_ID=${IOS_TEAM_ID}.${IOS_BUNDLE_ID}`.
3. Else backend uses placeholder `TEAMID.com.example.app` and logs a warning.

## ngrok helper

For physical-device flows with associated domains:

```bash
./samples/backend-ktor/start-server.sh
```

This helper updates root `local.properties` with `WEBAUTHN_DEMO_ENDPOINT`, `WEBAUTHN_DEMO_RP_ID`, and `WEBAUTHN_DEMO_ORIGIN`, then starts the backend with matching association values.
