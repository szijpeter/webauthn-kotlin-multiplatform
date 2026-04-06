# Client Stack

Last reviewed: 2026-04-06

The client side is organized around shared orchestration in common Kotlin code, with thin platform bridges on Android and iOS.

## Core Shape

- `webauthn-client-core` owns the shared ceremony logic and typed client APIs.
- `webauthn-client-android` bridges into Credential Manager.
- `webauthn-client-ios` bridges into AuthenticationServices.
- `webauthn-client-compose` provides remembered helpers for Compose-driven apps.
- `webauthn-client-json-core` is an optional raw JSON interop layer.
- `webauthn-network-ktor-client` is the default transport helper for `/webauthn/*` backends.
- `webauthn-client-prf-crypto` adds PRF-derived application crypto helpers on top of passkey flows.

## Practical Flow

1. The host app asks the backend for start options.
2. Shared client orchestration validates/maps those inputs into a platform-ready flow.
3. Android or iOS platform APIs perform the passkey prompt.
4. Shared client code maps the platform result back into a typed finish payload.
5. The app sends the finish payload to the backend.

Compose apps can keep most of the view-facing wiring in `rememberPasskeyClient(...)` and `rememberPasskeyController(...)`.

## Important Boundaries

- Shared business logic belongs in `webauthn-client-core`.
- Platform modules should stay narrow and mostly concerned with OS API translation and error mapping.
- JSON interop is optional and separate from the typed core.
- Transport is optional and should not be mistaken for the client core itself.

## Current Status Snapshot

From the current implementation/status docs:

- shared typed client orchestration is in place
- Android and iOS bridges are usable and deliberately thin
- Compose helpers exist for retained-controller usage
- PRF helpers are available for apps that need post-auth crypto material
- more device/provider/runtime matrix hardening is still expected, especially around platform-specific behavior

## Where To Go Next

- For the backend side of the same ceremony, read [`server-stack.md`](./server-stack.md).
- For runnable examples, read [`samples-and-demos.md`](./samples-and-demos.md).
- For maturity and next priorities, read [`status-and-roadmap.md`](./status-and-roadmap.md).

## Canonical Source Anchors

- Root client adoption section: [`README.md`](../../README.md)
- Client-first execution notes: [`docs/CLIENT_FIRST_EXECUTION.md`](../CLIENT_FIRST_EXECUTION.md)
- Client benchmark notes: [`docs/CLIENT_API_BENCHMARKS.md`](../CLIENT_API_BENCHMARKS.md)
- Sample Compose app: [`samples/compose-passkey/README.md`](../../samples/compose-passkey/README.md)
