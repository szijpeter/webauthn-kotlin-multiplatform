# Implementation Status

This document tracks what is implemented today and the current maturity by module.

Last updated: 2026-03-01

## Status Legend

- `Production-leaning`: core behavior implemented and tested; hardening continues.
- `Beta`: usable for development/testing; behavior surface still evolving.
- `Scaffold`: structural/API foundation in place; significant implementation remains.

## Overall Snapshot

- Protocol model and core validation baselines are implemented with strict negative-path tests.
- JVM server flow is implemented with ceremony orchestration and store contract coverage.
- Attestation verification includes hardened TPM and Android Key policy checks with expanded tests.
- JVM crypto remains Signum-first (`supreme` + `indispensable-cosef` + `indispensable-josef`) with JCA only for PKIX/X.509 trust duties.
- Client architecture moved to shared orchestration in `webauthn-client-core` (`DefaultPasskeyClient`) with thin Android/iOS platform bridges.
- Client typed APIs are isolated in `webauthn-client-core`; raw JSON client APIs are optional via `webauthn-client-json-core`.
- Compose integration helpers now exist in `webauthn-client-compose` with `rememberPasskeyClient` and lightweight operation state.
- Model/serialization transport now includes authenticator attachment, attestation conveyance preference, and authenticator transports.
- Network interop now supports both native library routes and external `PASSKEY_ENCRYPTION_POC` profile routes.

## Plan Progress (Estimated)

- Phase 1 (Client readiness/interoperability): ~65% complete.
- Phase 2 (Conformance/Security): ~75% complete.
- Phase 3 (Server robustness): ~70% complete.
- Phase 4-5 (DX/release): mostly pending.

## Module Maturity

| Module | Maturity | Implemented | Gaps / Risks |
|---|---|---|---|
| `webauthn-model` | Production-leaning | Typed protocol models, strict base64url behavior, value semantics tests, L3 extension models (PRF eval/evalByCredential, LargeBlob read/write, Related Origins), authenticator transports/attachment and attestation preference models | Continued edge-case coverage for uncommon protocol combinations |
| `webauthn-core` | Production-leaning | Core ceremony validation (type/challenge/origin/rpIdHash/UP/UV-policy/BE-BS-consistency/signCount/allowCredentials), allowedOrigins (Related Origins), broad negative-path tests, extension processing hooks, LargeBlob validation, PRF missing-output checks | Additional L3 extension hardening |
| `webauthn-serialization-kotlinx` | Beta | DTO mapping + authData parsing, round-trip tests, attachment/attestation/transports mapping | Deeper COSE/CBOR vector coverage |
| `webauthn-crypto-api` | Beta | Lean cross-module contracts (`SignatureVerifier`, `AttestationVerifier`, `TrustAnchorSource`, `RpIdHasher`, `CoseAlgorithm`, `coseAlgorithmFromCode`, payload models) | Additional implementations and cross-platform behavior parity |
| `webauthn-server-jvm-crypto` | Beta | Signum-first crypto path (digest, COSE decode, signature verification, JOSE SafetyNet decode), `none`/`packed`/`android-key`/`apple`/`tpm`/`android-safetynet`/`fido-u2f` verifiers, deterministic malformed/unsupported COSE rejection vectors, unified trust-chain flow through `TrustChainVerifier` | Broader attestation vector and trust-anchor coverage depth |
| `webauthn-server-core-jvm` | Beta | Registration/authentication service flow + rpId hash verification + in-memory stores + failure-path tests + persistence race tests + shared store-contract tests validated on in-memory and H2-backed stores | Broader external store implementations beyond H2 contract adapter |
| `webauthn-server-ktor` | Beta | Thin route adapters + tests | Operational hardening and sample-level integration depth |
| `webauthn-client-core` | Beta | Shared typed ceremony orchestration (`DefaultPasskeyClient`), deterministic invalid-options vs platform error behavior, capability model | More extension-focused policy helpers and fixture coverage |
| `webauthn-client-json-core` | Beta | Optional raw JSON client APIs (`JsonPasskeyClient`), replaceable codec contract (`PasskeyJsonCodec`), default kotlinx codec | Additional fixture depth and profile-oriented JSON interop coverage |
| `webauthn-client-compose` | Beta | Compose integration helpers (`rememberPasskeyClient`, `rememberPasskeyClientState`) and lightweight operation state model | Broader UI/runtime lifecycle coverage across host app patterns |
| `webauthn-client-android` | Beta | Thin Credential Manager bridge, deterministic platform error mapping, capability reporting, shared-core delegation | Lifecycle and OEM/provider compatibility hardening |
| `webauthn-client-ios` | Beta | Thin AuthenticationServices bridge, deterministic NSError mapping, capability reporting, shared-core delegation | More runtime/device matrix coverage |
| `webauthn-network-ktor-client` | Production-leaning | Transport helper client + payload tests, Related Origins fetcher, backend profile interop (`LIBRARY_ROUTES`, `PASSKEY_ENCRYPTION_POC`) | Retry/error policy hardening and broader profile fixtures |
| `webauthn-attestation-mds` | Scaffold/Beta | Optional trust source module and tests | Full attestation format/trust-chain verification depth |
| `samples:*` | Scaffold/Beta | Runnable backend/android/ios sample structure | End-to-end realistic passkey flows and docs depth |

## Validation Coverage Status

Implemented and traced in `spec-notes/webauthn-l3-validation-map.md`:

- `clientData` type/challenge/origin checks
- `authenticatorData` rpIdHash length and UP flag checks
- signCount non-increase invalid case
- strict base64url parsing guarantees
- allowCredentials membership enforcement

Pending high-impact coverage:

- L3 extension runtime hardening (PRF computation context hooks and richer authenticator interoperability vectors)

## Current Quality Gates

Local:

- Fast advisory: `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
- Strict blocking: `tools/agent/quality-gate.sh --mode strict --scope changed --block true`

Docs trace requirements in strict mode:

- Spec trace: `spec-notes/webauthn-l3-validation-map.md` for validator/model semantic changes.
- Status trace: `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md` for core/security-critical changes.
