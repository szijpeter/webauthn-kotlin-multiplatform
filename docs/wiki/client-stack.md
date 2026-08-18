# Client Stack

Last reviewed: 2026-08-19

The client side separates typed platform operations from generic ceremony orchestration, with thin platform bridges on Android and iOS.

## Core Shape

- `webauthn-client-core` owns the raw typed client contract and platform-independent client rules.
- `webauthn-client-flow` owns state-free ceremony orchestration with opaque backend state and application-defined output.
- `webauthn-client-ktor` adapts that flow to HTTP without choosing serialization.
- `webauthn-client-ktor-kotlinx` is the opt-in default `/webauthn/...` contract composition.
- `webauthn-client-platform` bridges into Credential Manager from `androidMain` and AuthenticationServices from `iosMain`.
- `webauthn-client-compose` provides remembered helpers for Compose-driven apps.
- `webauthn-client-json-core` is an optional raw JSON interop layer.
- `webauthn-network-ktor-client` is retained only for the staged legacy-controller migration.
- `webauthn-client-prf-crypto` adds PRF-derived application crypto helpers on top of passkey flows.

## Practical Flow

1. The host app asks the backend for start options.
2. `PasskeyFlow` carries backend state and hands typed options to `PasskeyClient`.
3. Android or iOS platform APIs perform the passkey prompt.
4. The platform client returns a byte-faithful raw credential response.
5. `PasskeyFlow` returns the opaque state and raw response to the application backend contract.

Compose apps can keep most of the view-facing wiring in `rememberPasskeyClient(...)` and `rememberPasskeyFlow(...)`; presentation state remains application-owned.

## Important Boundaries

- Typed platform operations belong in `webauthn-client-core`; start/prompt/finish sequencing belongs in `webauthn-client-flow`.
- Platform modules should stay narrow and mostly concerned with OS API translation and error mapping.
- JSON interop is optional and separate from the typed core.
- Transport is optional and should not be mistaken for the client core itself.
- The neutral Ktor adapter owns no engine or serializer; those choices remain in the app or opt-in Kotlinx module.

## Current Status Snapshot

From the current implementation/status docs:

- typed platform operations and generic ceremony orchestration are in place
- Android and iOS bridges are usable and deliberately thin
- Compose helpers remember platform clients and `PasskeyFlow`; presentation state remains application-owned
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
- Sample Compose app: [`sample/compose-passkey/README.md`](../../sample/compose-passkey/README.md)
