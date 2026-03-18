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
2. Keep `serialization = "1.9.0"` pinned in `gradle/libs.versions.toml` until compatibility is resolved.
3. Keep captured Android assertion-vector regression tests green (`ServiceSmokeTest.authenticationFinishSupportsCapturedAndroidAssertionVector` and `ServiceSmokeTest.jvmSignatureVerifierSupportsCapturedAndroidAssertionVector`).
4. Revisit `1.10.x` only after [a-sit-plus/signum#415](https://github.com/a-sit-plus/signum/issues/415) is resolved.

## Transport and Explicit-Type Adoption (2026-03-18)

`webauthn-network-ktor-client` now uses:

- `com.github.skydoves:sandwich`
- `com.github.skydoves:sandwich-ktor`

Decision:

1. Use `ApiResponse` in transport internals to reduce response/error mapping clutter while preserving existing domain behavior.
2. Keep `sandwich` scoped to transport adapter internals; do not leak `ApiResponse` into public module contracts.
3. Preserve current redaction, rejection semantics, and `PasskeyFinishResult` mapping so behavior remains stable for callers.

`webauthn-model` now exposes selected explicit types via:

- `org.kotools:types`

Decision:

1. Use `NotBlankString` for public fields where blank content is invalid by contract.
2. Use `NotEmptyList` for public collection fields where empty values were previously runtime-invalid.
3. Keep WebAuthn domain wrappers (`RpId`, `Challenge`, `CredentialId`, `Base64UrlBytes`, and related fixed-size wrappers) as project-owned types.
4. Keep conversion helpers centralized (`toNotBlankStringOrThrow`, `toNotEmptyListOrThrow`) to avoid repeated low-signal validation code at call sites.

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

## Immutable Byte Contracts

Public shared model contracts no longer expose raw `ByteArray` properties for value objects.

Decision:

1. Keep existing domain wrappers that already encode opaque binary values well (`Base64UrlBytes`, `Challenge`, `CredentialId`, `UserHandle`).
2. Use `Base64UrlBytes` as the shared generic immutable byte value type, with narrow wrappers only where domain invariants matter.
3. Use narrow domain wrappers where fixed-size invariants matter (`RpIdHash`, `Aaguid`).
4. Keep `webauthn-crypto-api` Signum-agnostic by exposing library-owned byte/domain types rather than third-party byte container types.

Rationale:

1. Kotlin `data class` equality and hashing are unsafe for array properties because arrays keep identity-based semantics.
2. Public `ByteArray` properties also leak mutability through shallow copies and shared references.
3. Repo-owned immutable wrappers give content-based equality, stable hashing, and defensive-copy boundaries without introducing a third-party public API dependency.
4. Fixed-size wrappers keep protocol invariants close to the type system and remove repeated length checks from call sites.
