# Roadmap

This roadmap tracks what to do next to reach a state-of-the-art WebAuthn Kotlin Multiplatform library.

Last updated: 2026-02-15

## North-Star Exit Criteria

1. Strong conformance coverage for core WebAuthn L3 semantics and major attestation paths.
2. Hardened server and client flows with predictable failure behavior and test depth.
3. Stable, documented module contracts for KMP consumers across JVM/Android/iOS.
4. High-signal CI and agent harness with low interruption and low waste.

## Phase 1: Conformance and Security Hardening (Immediate)

1. Attestation format matrix hardening (`packed`, `tpm`, `android-key`, `android-safetynet`, `apple`, `none`).
2. CBOR/COSE vector-based parser/validator expansion.
3. UV-required and BE/BS branching policy behavior coverage.
4. Core negative-path expansion tied to spec map rows.

Definition of done:

- Each new rule is reflected in tests and `spec-notes/webauthn-l3-validation-map.md`.

## Phase 2: Server Robustness and Store Semantics

1. Strengthen registration/authentication finish-path invariants.
2. Add replay, race, and persistence-oriented scenarios.
3. Expand server-ktor integration coverage.

Definition of done:

- JVM server behavior is deterministic under failure/race scenarios with test proof.

## Phase 3: Platform Runtime Hardening

1. Android Credential Manager lifecycle/error edge handling.
2. iOS AuthenticationServices delegate lifecycle/error handling.
3. Cross-platform client-core policy consistency.

Definition of done:

- Android/iOS adapters are beyond scaffold-level and validated by realistic flow tests.

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

Definition of done:

- Release candidate branch passes strict gate and CI with no unresolved critical gaps.

## Active Priorities (Next 3)

1. Implement attestation verification matrix and trust-path tests.
2. Expand CBOR/COSE conformance vectors with strict negative cases.
3. Harden server-core-jvm finish flow and persistence/race behavior tests.
