# Dependency Decisions

## Native Swift PRF Crypto Boundary

The native Swift package keeps WebAuthn option/response handling and platform ceremonies in the shared
Kotlin implementation, but derives and contains its PRF session key with CryptoKit. The published iOS
provider used by `webauthn-client-prf-crypto` currently embeds an AES object with an iOS 18.5 deployment
minimum; statically linking it would make the complete Swift package incompatible with its documented
iOS 16 baseline.

This is a deliberately narrow platform fallback: HKDF-SHA-256 key derivation, SHA-256 key fingerprinting,
and AES-256-GCM session operations only. A checked-in derivation vector is asserted by Kotlin tests, Swift
tests, and the semantic parity checker. Revisit the fallback if the provider can be linked without raising
the Swift package deployment target.

## Current State

`webauthn-server-jvm-crypto` is Signum-first:

- `at.asitplus.signum:supreme-jvm:0.12.0`
- `at.asitplus.signum:indispensable-cosef-jvm:3.20.0`
- `at.asitplus.signum:indispensable-josef-jvm:3.20.0`

These power runtime hashing, COSE decoding, signature parsing/verification, and SafetyNet JWS decoding.

`kotlinx-serialization` is unpinned and currently set to `1.10.0`.
The failing combination (`1.10.0` with older Signum runtime artifacts) is now avoided by upgrading the Signum set together.
Upstream tracking context: [a-sit-plus/signum#415](https://github.com/a-sit-plus/signum/issues/415) and fix PR [a-sit-plus/signum#416](https://github.com/a-sit-plus/signum/pull/416) included in Signum `3.20.0` / Supreme `0.12.0`.

Compatibility policy:

1. Keep runtime Signum-only (no JCA fallback in production paths).
2. Keep `serialization` + `signum` + `signum-indispensable` updated as a coordinated dependency set.
3. Keep captured Android assertion-vector regression tests green (`ServiceSmokeTest.authenticationFinishSupportsCapturedAndroidAssertionVector` and `ServiceSmokeTest.jvmSignatureVerifierSupportsCapturedAndroidAssertionVector`).
4. Treat single-dependency bumps that split this set as unsafe until the vector checks pass on that exact mix.

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
- **Coroutine cancellation rule:** `CancellationException` is control flow, not a domain failure. Rethrow it at suspend boundaries before mapping to `PasskeyResult`/`ValidationResult`.
- **Standard helper pattern:** Use `runSuspendCatching(...)` and `mapSuspendCatching(...)` as coroutine-safe drop-in replacements for stdlib `runCatching`/`mapCatching` in suspend contexts. Use `suspendCatchingNonCancellation(...)` when both cancellation rethrow and fatal-exception filtering (`nonFatalOrThrow`) are needed. Use `rethrowCancellationOrFatal(...)` for manual throwable paths.
- **External dependency decision:** Self-owned utilities in `webauthn-runtime-core` were chosen over external libraries (Arrow, kotlin-result) because the required functionality is ~30 lines and avoids adding a new transitive dependency. See [kotlinx.coroutines#1814](https://github.com/Kotlin/kotlinx.coroutines/issues/1814) for background.
- **Shared module:** `webauthn-runtime-core` owns these coroutine-boundary helpers for client/network adapter reuse.

## Client Runtime Dependencies

`webauthn-client-core` is typed-only and serializer-agnostic.
It does not depend on `kotlinx-serialization-json` or `:core:webauthn-json-kotlinx`.

Raw JSON API support is optional and lives in `webauthn-client-json-core`, which provides:
- `JsonPasskeyClient`
- `DefaultJsonPasskeyClient`
- `withJsonSupport(WebAuthnJsonCodec)`

The neutral codec contract lives in `webauthn-json-api`. `webauthn-client-json-core` requires callers
to supply that codec and does not resolve `webauthn-json-kotlinx` through its published metadata.

Policy:

1. Keep the platform wrappers in `webauthn-client-platform` thin and avoid moving shared logic back into target-specific source sets.
2. Keep the API boundary domain-owned (`PasskeyClient`, `PasskeyResult`, `PasskeyClientError`) even when platform SDK errors are richer.
3. Prefer additive capability flags (`PasskeyCapabilities`) over target-specific branching in public API signatures.
4. Keep serialization replaceable through `WebAuthnJsonCodec`; choose `webauthn-json-kotlinx` only in an explicit default/integration layer.

`webauthn-client-defaults` is that explicit platform composition layer. Depending on it intentionally
selects `webauthn-json-kotlinx` for Android convenience; consumers requiring dependency-pure codec
replacement depend on `webauthn-client-platform` and provide their codec directly.

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
