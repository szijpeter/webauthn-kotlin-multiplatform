# Ktor backend sample

A Ktor backend for local and mobile end-to-end passkey flows.

## Routes

- `POST /webauthn/registration/start`
- `POST /webauthn/registration/finish`
- `POST /webauthn/authentication/start`
- `POST /webauthn/authentication/finish`
- `POST /attestation/options` (when the registration compatibility adapter is enabled)
- `POST /attestation/result` (when the registration compatibility adapter is enabled)
- `GET /health`
- `GET /.well-known/assetlinks.json`
- `GET /.well-known/apple-app-site-association`
- `GET /apple-app-site-association`
- `GET /webauthn/cli/browser`

## Run

<!-- doc-example: id=sample-backend-ktor-readme-bash-1; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:backend-ktor:run
```

Environment variables:

- `PORT` (default `8080`)
- `WEBAUTHN_SAMPLE_ATTESTATION` (`STRICT` default, set `NONE` to explicitly disable strict attestation verification for local bring-up)
- `ANDROID_PACKAGE_NAME` (default `dev.webauthn.samples.composepasskey.android`)
- `ANDROID_SHA256` (default placeholder; set for real-device app-link verification)
- `IOS_APP_ID` (canonical iOS app ID for AASA `webcredentials.apps`, default placeholder)
- `IOS_TEAM_ID` (optional helper input, used to derive `IOS_APP_ID` when `IOS_APP_ID` is unset)
- `IOS_BUNDLE_ID` (optional helper input, used to derive `IOS_APP_ID` when `IOS_APP_ID` is unset)
- `WEBAUTHN_CONFORMANCE_ENABLED` (`false` by default; set `true` only for the registration compatibility adapter)
- `WEBAUTHN_CONFORMANCE_RP_ID` (server-controlled RP ID, default `localhost`)
- `WEBAUTHN_CONFORMANCE_RP_NAME` (server-controlled RP display name)
- `WEBAUTHN_CONFORMANCE_ORIGIN` (server-controlled expected origin, default `https://localhost:${PORT}`)

`IOS_APP_ID` resolution:

1. If `IOS_APP_ID` is set, it is used as-is.
2. Else if both `IOS_TEAM_ID` and `IOS_BUNDLE_ID` are set, backend derives `IOS_APP_ID=${IOS_TEAM_ID}.${IOS_BUNDLE_ID}`.
3. Else backend uses placeholder `TEAMID.com.example.app` and logs a warning.

## FIDO server registration compatibility canary

The optional `/attestation/options` and `/attestation/result` routes adapt the
sample backend to the FIDO server testing API's registration payload shape. They
are disabled by default and intentionally cover registration only; they are a
compatibility canary, not FIDO certification or a complete conformance server.

The adapter always uses `WEBAUTHN_CONFORMANCE_RP_ID`,
`WEBAUTHN_CONFORMANCE_RP_NAME`, and `WEBAUTHN_CONFORMANCE_ORIGIN` as trusted
server configuration. RP or origin values supplied by the caller are ignored,
and unsupported extension input is not reflected into creation options.

Run the local canary test with:

<!-- doc-example: id=sample-backend-ktor-readme-bash-3; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew :sample:backend-ktor:communityConformanceE2eTest
```

## ngrok helper

For physical-device flows with associated domains:

<!-- doc-example: id=sample-backend-ktor-readme-bash-2; owner=markdown; verify=syntax; audience=consumer -->
```bash
./sample/backend-ktor/start-server.sh
```

This helper updates root `local.properties` with `WEBAUTHN_DEMO_ENDPOINT`,
`WEBAUTHN_DEMO_RP_ID`, and the iOS/web `WEBAUTHN_DEMO_ORIGIN`, then starts the
backend with matching association values. The Android host derives its
`android:apk-key-hash:...` ceremony origin from the installed app's signing
certificate; `ANDROID_SHA256` must describe that same certificate for the served
Digital Asset Links statement.
