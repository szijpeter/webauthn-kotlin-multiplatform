# Module Map

Last reviewed: 2026-04-06

The repository uses a layered module model. Core protocol and validation concerns stay separate from crypto, server services, transport adapters, and platform clients.

## Layer Model

| Layer | Key modules | Role |
| --- | --- | --- |
| Protocol model | `webauthn-model` | Typed WebAuthn protocol and value wrappers |
| Validation and serialization | `webauthn-core`, `webauthn-serialization-kotlinx`, `webauthn-cbor-core`, `webauthn-runtime-core` | Validation, parsing, DTO mapping, and shared runtime helpers |
| Crypto | `webauthn-crypto-api`, `webauthn-server-jvm-crypto` | Crypto contracts plus JVM attestation/signature implementation |
| Server | `webauthn-server-core-jvm`, `webauthn-server-ktor`, `webauthn-server-store-exposed`, `webauthn-attestation-mds` | Ceremony services, route adapters, persistence adapters, optional trust metadata |
| Client | `webauthn-client-core`, `webauthn-client-json-core`, `webauthn-client-compose`, `webauthn-client-android`, `webauthn-client-ios`, `webauthn-client-prf-crypto`, `webauthn-network-ktor-client` | Shared client logic, platform bridges, Compose helpers, transport, and PRF crypto helpers |

## Published Surface

The published artifact surface is coordinated as one release train. The main published families are:

- BOM: `platform:bom`
- Foundation: `webauthn-cbor-core`, `webauthn-model`, `webauthn-runtime-core`, `webauthn-serialization-kotlinx`, `webauthn-core`
- Crypto and server: `webauthn-crypto-api`, `webauthn-server-jvm-crypto`, `webauthn-server-core-jvm`, `webauthn-server-ktor`, `webauthn-server-store-exposed`, `webauthn-attestation-mds`
- Client: `webauthn-client-core`, `webauthn-client-json-core`, `webauthn-client-compose`, `webauthn-client-android`, `webauthn-client-ios`, `webauthn-client-prf-crypto`, `webauthn-network-ktor-client`

Not published:

- `platform:constraints`
- `samples:*`
- `build-logic`

## Recommended Adoption Paths

### Server-first

- `webauthn-model`
- `webauthn-core`
- `webauthn-crypto-api`
- `webauthn-server-jvm-crypto`
- `webauthn-server-core-jvm`
- optional: `webauthn-server-ktor`
- optional: `webauthn-server-store-exposed`
- optional: `webauthn-attestation-mds`

### Client-first

- `webauthn-client-core`
- optional: `webauthn-client-json-core`
- `webauthn-client-android` and/or `webauthn-client-ios`
- optional: `webauthn-client-compose`
- optional: `webauthn-network-ktor-client`
- optional: `webauthn-client-prf-crypto`

### Mixed app + backend adoption

Use [`platform/bom/README.md`](../../platform/bom/README.md) to keep versions aligned across published artifacts.

## Design Rules Worth Remembering

- `webauthn-model` and `webauthn-core` must remain free of platform and network dependencies.
- `webauthn-client-core` owns shared client business logic; Android and iOS modules stay thin.
- Ktor modules are adapters, not the core business layer.
- Optional trust sources like MDS should remain separable from the main validation path.

## Canonical Source Anchors

- Root architecture section: [`README.md`](../../README.md)
- Architecture doc: [`docs/architecture.md`](../architecture.md)
- Published surface policy: [`docs/ai/STEERING.md`](../ai/STEERING.md)
- Settings module list: [`settings.gradle.kts`](../../settings.gradle.kts)
