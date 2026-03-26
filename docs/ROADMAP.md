# Roadmap

This roadmap tracks what to do next to reach a state-of-the-art WebAuthn Kotlin Multiplatform library.

Last updated: 2026-03-26

## North-Star Exit Criteria

1. Strong conformance coverage for core WebAuthn L3 semantics and major attestation paths.
2. Hardened server and client flows with predictable failure behavior and test depth.
3. Stable, documented module contracts for KMP consumers across JVM/Android/iOS.
4. High-signal CI and agent harness with low interruption and low waste.

## Immediate Execution Strategy (Client First)

1. Keep client implementation velocity independent from first-party backend hardening.
2. Use explicit backend contracts and the in-repo sample backend for client validation.
3. Keep shared client business logic in `webauthn-client-core`; platform wrappers stay thin.
4. Drive all client API and behavior decisions from WebAuthn spec requirements first.

## Phase 1: Client Readiness and Interoperability (Immediate)

1. Keep shared typed ceremony orchestration in `webauthn-client-core` and maintain optional JSON APIs in `webauthn-client-json-core`.
2. Keep Android Credential Manager and iOS AuthenticationServices adapters as thin platform bridges.
3. Maintain interop paths for host-provided backend contracts and the local sample backend app (`samples/backend-ktor`).
4. Verify extension transport and response mapping for PRF and Large Blob semantics.
5. Align client API ergonomics against trusted ecosystem SDKs while preserving standards-first behavior.

Definition of done:

- Android/iOS clients are runnable end-to-end against at least one non-repo backend and one local dev backend.

## Phase 2: Conformance and Security Hardening

1. Attestation format matrix hardening (`packed`, `tpm` (done), `android-key` (done), `android-safetynet`, `apple`, `none`).
2. CBOR/COSE vector-based parser/validator expansion.
3. UV-required and BE/BS branching policy behavior coverage.
4. Core negative-path expansion tied to spec map rows.

Definition of done:

- Each new rule is reflected in tests and `spec-notes/webauthn-l3-validation-map.md`.

## Phase 3: Server Robustness and Store Semantics

1. Strengthen registration/authentication finish-path invariants.
2. Add replay, race, and persistence-oriented scenarios (in-memory and H2-backed store contracts done).
3. Expand server-ktor integration coverage.
4. JetBrains Exposed store module (`webauthn-server-store-exposed`) with `ExposedChallengeStore`, `ExposedCredentialStore`, `ExposedUserAccountStore` (done).
5. Strict UV policy coverage: `ChallengeSession` persists `userVerification`, `Services.kt` maps to `UserVerificationPolicy` for core validator (done).

Definition of done:

- JVM server behavior is deterministic under failure/race scenarios with test proof.

## Phase 4: Developer Experience and API Stability

1. API surface review and compatibility expectations by module maturity.
2. Documentation quality pass for integration guidance.
3. Sample app hardening for reference-quality usage.

Definition of done:

- External consumers can adopt core/server/client modules with low ambiguity.

## Phase 5: Release Readiness

1. Release checklist formalization and CI parity confirmation.
2. Stabilization pass on performance, logging, and diagnostics.
3. Versioning/release notes discipline with migration notes.
4. Maven Central publication path, BOM guidance, and public-module documentation.

Definition of done:

- Release candidate branch passes strict gate and CI with no unresolved critical gaps.

## Active Priorities (Next 3)

1. Continue remaining attestation trust-path hardening (`android-safetynet`, `apple`) with vectors.
2. Keep `kotlinx-serialization` pinned to `1.9.0` until Signum compatibility blocker [a-sit-plus/signum#415](https://github.com/a-sit-plus/signum/issues/415) is resolved, then rerun captured vector checks during unpin.
3. TODO (deferred, non-blocking): add sample-app walkthrough recordings (backend + Android + iOS Compose hosts) for registration, sign-in, and PRF demo flow before broader outreach.
