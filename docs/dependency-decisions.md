# Dependency Decisions

## Current State

`webauthn-server-jvm-crypto` is Signum-first:

- `at.asitplus.signum:supreme-jvm:0.11.3`
- `at.asitplus.signum:indispensable-cosef-jvm:3.19.3`
- `at.asitplus.signum:indispensable-josef-jvm:3.19.3`

These power runtime hashing, COSE decoding, signature parsing/verification, and SafetyNet JWS decoding.

`kotlinx-serialization` remains pinned to `1.9.x` for now.
We attempted an unpin to `1.10.0` with captured Android assertion vectors and observed signature verification regressions in Signum-backed authentication verification.
Tracking issue: [a-sit-plus/signum#415](https://github.com/a-sit-plus/signum/issues/415).

Unpin policy:

1. Keep runtime Signum-only (no JCA fallback in production paths).
2. Re-run `tools/compat/run-signum-serialization-matrix.sh` target combos on dependency-sensitive changes.
3. Move to `1.10.x` only after matrix passes for target combo(s) with Signum runtime.

## Remaining JCA Boundary

JCA/JDK APIs are intentionally used only for PKI trust duties:

1. X.509 certificate parsing and extension access.
2. Trust-anchor loading.
3. PKIX path validation (`CertPathValidator`, `PKIXParameters`, `TrustAnchor`).

No runtime provider toggle or legacy crypto path is kept.

## API Boundary

`webauthn-crypto-api` stays library-owned and Signum-agnostic. Current public surface:

- `SignatureVerifier`
- `AttestationVerifier`
- `TrustAnchorSource`
- `RpIdHasher`
- `CoseAlgorithm`
- `coseAlgorithmFromCode`
- payload models

This keeps core/server contracts stable and independent from any single crypto vendor type system.

## Internal Result Pipelines

`at.asitplus:kmmresult` is approved for targeted internal pipeline ergonomics.
- **Role:** Helps internal sequential success/failure mapping (`catching`, `.transform`) where a single failure cause is expected.
- **Rule:** `KmmResult` remains an internal implementation detail and must never be exposed in public API contracts. External callers depend on domain-specific result wrappers (for example `PasskeyResult`, `ValidationResult`).

## Client Runtime Dependencies

`webauthn-client-core` is typed-only and serializer-agnostic.
It does not depend on `kotlinx-serialization-json` or `:webauthn-serialization-kotlinx`.

Raw JSON API support is optional and lives in `webauthn-client-json-core`, which provides:
- `JsonPasskeyClient`
- `PasskeyJsonMapper`
- `KotlinxPasskeyJsonMapper`

Policy:

1. Keep platform wrappers thin (`webauthn-client-android`, `webauthn-client-ios`) and avoid moving shared logic back into target-specific modules.
2. Keep the API boundary domain-owned (`PasskeyClient`, `PasskeyResult`, `PasskeyClientError`) even when platform SDK errors are richer.
3. Prefer additive capability flags (`PasskeyCapabilities`) over target-specific branching in public API signatures.
4. Keep serialization strategy replaceable through `PasskeyJsonMapper` in optional JSON module so alternative mappers can be used without core API changes.
