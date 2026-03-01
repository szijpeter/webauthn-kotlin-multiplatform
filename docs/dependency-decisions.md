# Dependency Decisions

## Current State

`webauthn-server-jvm-crypto` is Signum-first:

- `at.asitplus.signum:supreme-jvm:0.11.3`
- `at.asitplus.signum:indispensable-cosef-jvm:3.19.3`
- `at.asitplus.signum:indispensable-josef-jvm:3.19.3`

These power runtime hashing, COSE decoding, signature parsing/verification, and SafetyNet JWS decoding.

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

`webauthn-client-core` is serializer-agnostic and does not depend on `kotlinx-serialization-json` or `:webauthn-serialization-kotlinx`.
JSON encoding/decoding is injected through `PasskeyJsonCodec`, implemented by platform modules.

Policy:

1. Keep platform wrappers thin (`webauthn-client-android`, `webauthn-client-ios`) and avoid moving shared logic back into target-specific modules.
2. Keep the API boundary domain-owned (`PasskeyClient`, `PasskeyResult`, `PasskeyClientError`) even when platform SDK errors are richer.
3. Prefer additive capability flags (`PasskeyCapabilities`) over target-specific branching in public API signatures.
4. Keep serialization strategy replaceable through `PasskeyJsonCodec` so alternative codecs can be used without core API changes.
