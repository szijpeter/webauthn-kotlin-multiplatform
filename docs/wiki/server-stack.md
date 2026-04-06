# Server Stack

Last reviewed: 2026-04-06

The server side centers on standards-first ceremony validation and JVM-focused orchestration.

## Core Shape

- `webauthn-core` validates ceremony semantics and authenticator data rules.
- `webauthn-crypto-api` defines the crypto and attestation contracts the rest of the stack depends on.
- `webauthn-server-jvm-crypto` provides the JVM crypto implementation, with Signum-first policy and attestation verifiers.
- `webauthn-server-core-jvm` provides framework-agnostic registration and authentication services.
- `webauthn-server-ktor` adds thin Ktor route adapters.
- `webauthn-server-store-exposed` adds Exposed-backed persistence implementations.
- `webauthn-attestation-mds` is an optional trust-source module for FIDO Metadata Service data.

## Practical Flow

1. The server starts a registration or authentication ceremony and returns options.
2. The client performs the platform passkey flow.
3. The server finish path validates challenge, origin, type, RP ID hash, flags, counters, and related ceremony invariants.
4. Crypto and attestation verification run through the configured verifier contracts.
5. Persistence modules store challenge and credential state when needed.

Validation and trust decisions remain server responsibilities, even when the client libraries are shared with the backend stack.

## Important Boundaries

- Core ceremony services stay framework-agnostic in `webauthn-server-core-jvm`.
- Ktor integration is intentionally thin.
- Persistence is modular rather than baked into the core service layer.
- Optional trust sources should not force themselves into simpler deployments.

## Current Status Snapshot

From the current status and roadmap docs:

- validation and server ceremony paths are among the most mature parts of the repo
- JVM crypto and attestation verification are implemented with continuing vector hardening
- Exposed-backed stores exist and already have contract coverage
- additional attestation matrix depth and broader operational hardening remain active work

## Where To Go Next

- For the shared and platform client side, read [`client-stack.md`](./client-stack.md).
- For the sample backend contract, read [`samples-and-demos.md`](./samples-and-demos.md).
- For release and compatibility implications of server changes, read [`quality-and-release.md`](./quality-and-release.md).

## Canonical Source Anchors

- Root server adoption section: [`README.md`](../../README.md)
- Architecture doc: [`docs/architecture.md`](../architecture.md)
- Dependency policy: [`docs/dependency-decisions.md`](../dependency-decisions.md)
- Sample backend: [`samples/backend-ktor/README.md`](../../samples/backend-ktor/README.md)
