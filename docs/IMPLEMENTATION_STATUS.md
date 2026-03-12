# Implementation Status

This document tracks what is implemented today and the current maturity by module.

Last updated: 2026-03-12

## Status Legend

- `Production-leaning`: core behavior implemented and tested; hardening continues.
- `Beta`: usable for development/testing; behavior surface still evolving.
- `Scaffold`: structural/API foundation in place; significant implementation remains.

## Overall Snapshot

- Protocol model and core validation baselines are implemented with strict negative-path tests.
- JVM server flow is implemented with ceremony orchestration and store contract coverage.
- Attestation verification includes hardened TPM and Android Key policy checks with expanded tests.
- Strict UV policy coverage: `ChallengeSession` persists `userVerification`; `Services.kt` maps to `UserVerificationPolicy` for core validator enforcement.
- JVM crypto remains Signum-first (`supreme` + `indispensable-cosef` + `indispensable-josef`) with JCA only for PKIX/X.509 trust duties.
- Client architecture moved to shared orchestration in `webauthn-client-core` (`DefaultPasskeyClient`) with thin Android/iOS platform bridges.
- Client typed APIs are isolated in `webauthn-client-core`; raw JSON client APIs are optional via `webauthn-client-json-core`.
- Compose integration helpers now exist in `webauthn-client-compose` with `rememberPasskeyClient` and lightweight operation state.
- Model/serialization transport now includes authenticator attachment, attestation conveyance preference, and authenticator transports.
- Shared model contracts now use `Base64UrlBytes` plus domain-specific fixed-size wrappers (`RpIdHash`, `Aaguid`) instead of public raw `ByteArray` properties.
- Shared byte/domain wrappers now use redacted `toString()` output, add named `ClientDataHash` and `CosePublicKey` values where the semantics matter, and keep the JVM signature verifier on typed COSE-key inputs.
- Packed attestation now derives flags and AAGUID from `authData` with explicit truncated-input rejection, and MDS trust lookup normalizes hyphenated AAGUID metadata entries.
- Network interop uses a default backend contract in `webauthn-network-ktor-client` and first-party sample backend routes under `samples/backend-ktor`.
- Samples include a Compose Multiplatform client-readiness app (Android host + iOS `MainViewController` entrypoint) that runs register/sign-in flows against the default `/webauthn/*` backend contract.
- Sample backend attestation policy now defaults to strict verification with explicit `NONE` opt-out for local bring-up only.
- Creation-options DTO decoding now honors legacy `authenticatorSelection.requireResidentKey=true` by mapping to `ResidentKeyRequirement.REQUIRED` when `residentKey` is absent.
- `AppleAttestationStatementVerifier` tests now use a hardened `authData` parser that explicitly rejects truncated credential data missing the public key.
- Compose sample config now derives default `rpId` from the runtime `endpointBase` constructor argument (instead of always using build-time endpoint defaults).
- Repository quality gates now run detekt across all Kotlin modules plus `build-logic` with a shared strict config (`maxIssues=0`, no baseline); CI uploads XML/HTML detekt reports per run.
- Review follow-up keeps `Base64UrlBytes.parse` and Related Origins fetch error handling on explicit `try/catch` paths, with coroutine cancellation propagation preserved in the Ktor metadata provider.
- Release-mode infrastructure is now active: coordinated `GROUP`/`VERSION_NAME` metadata, Maven Central publishing workflow, BCV baselines for supported published modules, and `publishToMavenLocal` preflight wiring.
- PR CI is now the blocking authority; local pre-push checks remain advisory so release work can iterate in PRs without bypassing verification.
- Local release-prep audit is green on 2026-03-12: strict full quality gate, `apiCheck`, `publishToMavenLocal`, and `verify-harness-sync`.
- Release docs now clarify that RP ID hashing examples are illustrative and production implementations must use SHA-256 before `RpIdHash.fromBytes`; PR template checks also require `publishToMavenLocal` when public API changes.
- MDS integration docs now call out the required initial `refreshIfStale(...)` load so `FidoMdsTrustSource` is populated before attestation verification begins.
- Public API hardening follow-up #59 is implemented in code: core validator boundaries now use typed wrappers (`WebAuthnClientDataType`, `Challenge`, `CredentialId`), request-options `rpId` is optional in model/DTO ABI, sensitive network payload `toString()` values are redacted, and client finish calls now return structured `PasskeyFinishResult`.

## Plan Progress (Estimated)

- Phase 1 (Client readiness/interoperability): ~75% complete.
- Phase 2 (Conformance/Security): ~85% complete.
- Phase 3 (Server robustness): ~80% complete.
- Phase 4-5 (DX/release): in progress.

## Module Maturity

| Module | Maturity | Implemented | Gaps / Risks |
|---|---|---|---|
| `webauthn-model` | Production-leaning | Typed protocol models, strict base64url behavior, value semantics tests, immutable byte/domain wrappers for binary protocol values, redacted byte-wrapper diagnostics, named `ClientDataHash`/`CosePublicKey` values, L3 extension models (PRF eval/evalByCredential, LargeBlob read/write, Related Origins), authenticator transports/attachment and attestation preference models | Continued edge-case coverage for uncommon protocol combinations |
| `webauthn-cbor-internal` | Beta | Shared strict CBOR byte scanner helpers for attestation/authenticator parsing, minimal-encoding rejection, common KMP module consumed via normal project dependencies | Internal helper module only; broader vector depth remains covered through consuming modules |
| `webauthn-core` | Production-leaning | Core ceremony validation (type/challenge/origin/rpIdHash/UP/UV-policy/BE-BS-consistency/signCount/allowCredentials), allowedOrigins (Related Origins), broad negative-path tests, extension processing hooks, LargeBlob validation, PRF missing-output checks | Additional L3 extension hardening |
| `webauthn-serialization-kotlinx` | Beta | DTO mapping + typed CBOR authData extraction, shared internal CBOR byte scanner usage, strict minimal CBOR/COSE rejection for registration parsing, round-trip tests, attachment/attestation/transports mapping | Deeper COSE/CBOR vector coverage |
| `webauthn-crypto-api` | Beta | Lean cross-module contracts (`SignatureVerifier`, `AttestationVerifier`, `TrustAnchorSource`, `RpIdHasher`, `CoseAlgorithm`, `coseAlgorithmFromCode`, payload models), typed `CosePublicKey` and `ClientDataHash` surfaces for crypto-relevant bytes | Additional implementations and cross-platform behavior parity |
| `webauthn-server-jvm-crypto` | Beta | Signum-first crypto path (digest, COSE decode, signature verification, JOSE SafetyNet decode), typed COSE-key verification boundary, `none`/`packed`/`android-key`/`apple`/`tpm`/`android-safetynet`/`fido-u2f` verifiers, deterministic malformed/unsupported COSE rejection vectors, shared internal CBOR byte scanner usage, strict minimal CBOR attestation parsing, packed-attestation `authData` length enforcement for AAGUID extraction, unified trust-chain flow through `TrustChainVerifier` | Broader attestation vector and trust-anchor coverage depth |
| `webauthn-server-core-jvm` | Beta | Registration/authentication service flow + rpId hash verification + in-memory stores + failure-path tests + persistence race tests + shared store-contract tests validated on in-memory and H2-backed stores, strict UV policy mapping through `Services.kt` | Broader external store implementations beyond H2 contract adapter |
| `webauthn-server-store-exposed` | Beta | JetBrains Exposed store module (`ExposedChallengeStore`, `ExposedCredentialStore`, `ExposedUserAccountStore`), forUpdate() row locking for challenge consumption, database-agnostic via Exposed, H2-backed contract tests + Docker-gated PostgreSQL Testcontainers tests, persists `ChallengeSession.extensions` via JSON | Additional database vendor testing and production hardening |
| `webauthn-server-ktor` | Beta | Thin route adapters + tests | Operational hardening and sample-level integration depth |
| `webauthn-client-core` | Beta | Shared typed ceremony orchestration (`DefaultPasskeyClient`), deterministic invalid-options vs platform error behavior, capability model | More extension-focused policy helpers and fixture coverage |
| `webauthn-client-json-core` | Beta | Optional raw JSON client APIs (`JsonPasskeyClient`), replaceable mapper contract (`PasskeyJsonMapper`), default kotlinx mapper | Additional fixture depth and profile-oriented JSON interop coverage |
| `webauthn-client-compose` | Beta | Compose integration helpers (`rememberPasskeyClient`, `rememberPasskeyController`) for controller-driven state | Broader UI/runtime lifecycle coverage across host app patterns |
| `webauthn-client-android` | Beta | Thin Credential Manager bridge, deterministic platform error mapping, capability reporting, shared-core delegation | Lifecycle and OEM/provider compatibility hardening |
| `webauthn-client-ios` | Beta | Thin AuthenticationServices bridge, deterministic NSError mapping, capability reporting, shared-core delegation | More runtime/device matrix coverage |
| `webauthn-network-ktor-client` | Production-leaning | Transport helper client + payload tests, Related Origins fetcher, default backend contract (`DefaultBackendContract`) | Retry/error policy hardening and broader contract fixtures |
| `webauthn-attestation-mds` | Beta | Optional trust source module and tests, normalized AAGUID lookup across hyphenated metadata and raw-byte authenticator values | Full attestation format/trust-chain verification depth |
| `samples:*` | Beta | Runnable backend/android/ios structure and Compose KMP readiness sample wired to default `/webauthn/*` contract via `samples/backend-ktor` | More real-device matrix coverage and extension-focused end-to-end examples |

## Validation Coverage Status

Implemented and traced in `spec-notes/webauthn-l3-validation-map.md`:

- `clientData` type/challenge/origin checks
- `authenticatorData` rpIdHash verification (with type-enforced fixed-size invariant) and UP flag checks
- signCount non-increase invalid case
- strict base64url parsing guarantees
- allowCredentials membership enforcement

Pending high-impact coverage:

- L3 extension runtime hardening (PRF computation context hooks and richer authenticator interoperability vectors)

## Current Quality Gates

Local:

- Fast advisory: `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
- Strict advisory: `tools/agent/quality-gate.sh --mode strict --scope changed --block false`
- API compatibility: `./gradlew apiCheck --stacktrace`
- Publish preflight: `./gradlew publishToMavenLocal --stacktrace`

Docs trace requirements in strict mode:

- Spec trace: `spec-notes/webauthn-l3-validation-map.md` for validator/model semantic changes.
- Status trace: `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md` for core/security-critical changes.
