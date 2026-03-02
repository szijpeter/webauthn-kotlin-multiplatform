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

## Endpoints

- `POST /register/options`
- `POST /register/verify?userId=<id>`
- `POST /authenticate/options`
- `POST /authenticate/verify?challenge=<challenge>`
- `GET /.well-known/assetlinks.json`
- `GET /.well-known/apple-app-site-association`
- `GET /apple-app-site-association`
- `GET /health`

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
