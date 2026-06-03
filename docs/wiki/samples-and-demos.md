# Samples And Demos

Last reviewed: 2026-04-06

The sample apps are reference integrations, not published library modules. They exist to prove end-to-end flows, show intended usage, and shorten onboarding.

## Main Reference Set

- `sample/backend-ktor`: demo backend exposing the default `/webauthn/*` contract plus health and associated-domain endpoints
- `sample/compose-passkey`: shared Compose Multiplatform sample module demonstrating register, sign-in, capability checks, debug logs, and PRF crypto demo flow
- `sample/compose-passkey-android`: Android host app for the shared Compose sample
- `sample/compose-passkey-ios`: iOS host app for the shared Compose sample
- `sample/passkey-cli`: experimental macOS-first native-authenticator CLI proof of concept
- `sample/android-passkey` and `sample/ios-passkey`: platform-specific sample apps outside the Compose path

## Default Demo Contract

The sample backend exposes:

- `POST /webauthn/registration/start`
- `POST /webauthn/registration/finish`
- `POST /webauthn/authentication/start`
- `POST /webauthn/authentication/finish`

This contract is the default assumed by `webauthn-network-ktor-client` and the Compose sample.

## Why These Matter

- They are the fastest way to understand the intended client/server wiring.
- They provide an end-to-end test bed for Android and iOS passkey work.
- They demonstrate associated-domain and local-dev environment setup details that do not belong in the library core.

## Practical Notes

- Physical-device flows are easiest through the `sample/backend-ktor/start-server.sh` helper, which aligns local properties with an ngrok domain.
- The Compose sample includes structured debug logging and a PRF demo, making it the highest-signal reference app for current client work.
- Android runtime success still depends on device/provider prerequisites such as Play services, screen lock, and a passkey-capable account.

## Canonical Source Anchors

- Sample overview in root docs: [`README.md`](../../README.md)
- Backend sample doc: [`sample/backend-ktor/README.md`](../../sample/backend-ktor/README.md)
- Compose sample doc: [`sample/compose-passkey/README.md`](../../sample/compose-passkey/README.md)
- Desktop/CLI notes: [`docs/DESKTOP_CLI_STRATEGY.md`](../DESKTOP_CLI_STRATEGY.md)
