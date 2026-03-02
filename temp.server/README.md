# temp.server

Development-only temporary backend for passkey client bring-up.

## Purpose

1. Unblock Android/iOS client implementation before first-party backend completion.
2. Provide WebAuthn-shaped registration/authentication endpoints with minimal setup.
3. Serve associated-domain files needed by mobile passkey providers.

## Warning

This server does not perform full cryptographic verification and must never be used in production.

## Requirements

- Node.js 18+

## Run

```bash
cd temp.server
npm start
```

Default URL: `http://localhost:8787`

## Run With ngrok (Recommended for Physical Devices)

The helper script below starts ngrok, derives `RP_ID`/`ORIGIN` from the tunnel URL, updates root `local.properties` (`WEBAUTHN_DEMO_*`), and runs `temp.server` with matching env values.

```bash
./temp.server/start-server.sh
```

Optional inputs (via environment or `local.properties`):

- `ngrok.domain` (or `NGROK_DOMAIN`) for a fixed ngrok domain
- `ANDROID_PACKAGE_NAME` (default `dev.webauthn.samples.composepasskey.android`)
- `ANDROID_SHA256` (if missing, script tries debug keystore fingerprint)
- `IOS_APP_ID` for AASA `webcredentials.apps`

## Endpoints

- `POST /register/options`
- `POST /register/verify?userId=<id>`
- `POST /authenticate/options`
- `POST /authenticate/verify?challenge=<challenge>`
- `GET /.well-known/assetlinks.json`
- `GET /.well-known/apple-app-site-association`
- `GET /apple-app-site-association`
- `GET /health`

Demo behavior notes:

- registration options return empty `excludeCredentials` to keep repeated registration possible
- registration verify stores both `rawId` and `id` when present
- authentication options return explicit `allowCredentials` and fall back to all in-memory credentials when user lookup misses

`/.well-known/assetlinks.json` includes both Android relations required for app-link verification and passkeys:

- `delegate_permission/common.handle_all_urls`
- `delegate_permission/common.get_login_creds`

## Environment Variables

- `PORT` (default `8787`)
- `RP_ID` (default `localhost`)
- `RP_NAME` (default `WebAuthn Kotlin MPP Temp Server`)
- `ORIGIN` (default `https://<RP_ID>`)
- `ANDROID_PACKAGE_NAME` (for `assetlinks.json`)
- `ANDROID_SHA256` (for `assetlinks.json`)
- `IOS_APP_ID` (for AASA `webcredentials.apps`)

## Client Interop

Use `WebAuthnInteropKtorClient` with `WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC` because the endpoint contract is intentionally compatible with that profile.

## Android Verification Reset

If Android reports a custom verifier code (for example `1024`) after changing tunnel domains, reset and re-verify:

```bash
adb shell pm reset-app-links dev.webauthn.samples.composepasskey.android
adb shell pm verify-app-links --re-verify dev.webauthn.samples.composepasskey.android
adb shell pm set-app-links-user-selection --user cur --package dev.webauthn.samples.composepasskey.android true all
adb shell pm get-app-links --user cur dev.webauthn.samples.composepasskey.android
```
