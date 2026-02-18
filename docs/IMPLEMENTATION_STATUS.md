# Implementation Status

This document tracks what is implemented today and the current maturity by module.

Last updated: 2026-02-18

## Status Legend

- `Production-leaning`: core behavior implemented and tested; hardening continues.
- `Beta`: usable for development/testing; behavior surface still evolving.
- `Scaffold`: structural/API foundation in place; significant implementation remains.

## Overall Snapshot

- Protocol model and core validation baselines are implemented with strict negative-path tests.
- JVM server flow is implemented with ceremony orchestration and smoke tests.
- Attestation verification now includes hardened TPM and Android Key policy checks with expanded tests.
- Attestation statement verifiers consume KMP-safe crypto abstractions (digest/COSE/certificate services) and a shared algorithm mapper; JVM layer uses a single JCA algorithm mapper for signature/key factory names.
- Platform clients (Android/iOS) have deterministic error mapping coverage, with response parsing still pending.
- CI lanes cover JVM checks, Android assemble, and iOS compile.

## Plan Progress (Estimated)

- Phase 1 (Conformance/Security): ~75% complete.
- Phase 2 (Server robustness): ~70% complete.
- Phase 3 (Platform runtime): ~45% complete.
- Phase 4-5 (DX/release): mostly pending.

## Module Maturity

| Module | Maturity | Implemented | Gaps / Risks |
|---|---|---|---|
| `webauthn-model` | Production-leaning | Typed protocol models, strict base64url behavior, value semantics tests, L3 extension models (PRF eval/evalByCredential, LargeBlob read/write, Related Origins) | Continued edge-case coverage for uncommon protocol combinations |
| `webauthn-core` | Production-leaning | Core ceremony validation (type/challenge/origin/rpIdHash/UP/UV-policy/BE-BS-consistency/signCount/allowCredentials), allowedOrigins (Related Origins), broad negative-path tests (incl. AAGUID model updates), extension processing hooks, LargeBlob validation, PRF missing-output checks | Additional L3 extensions hardening |
| `webauthn-serialization-kotlinx` | Beta | DTO mapping + authData parsing, round-trip tests | Deeper COSE/CBOR vector coverage |
| `webauthn-crypto-api` | Beta | Abstraction interfaces plus shared `coseAlgorithmFromCode` mapper; KMP-safe attestation crypto services (digest, COSE decode/normalize, certificate signature/inspection/chain validation) and neutral DTOs | Additional implementations and cross-provider behavior parity |
| `webauthn-server-jvm-crypto` | Beta | JCA/JCE crypto baseline + shared `JcaAlgorithmMapper` + dedicated COSE parser (`JvmCoseParser`, `CoseToSpkiConverter`) with documented support matrix (EC2 P-256, RSA; OKP/Ed25519 unsupported) + deterministic failure (no raw-byte fallback) + P1-006 malformed/unsupported COSE conformance vectors + `none`/`packed`/`android-key`/`apple`/`tpm`/`android-safetynet`/`fido-u2f` verifiers + unified `TrustChainVerifier` injection across all formats + deterministic JSON-based JWS parsing for SafetyNet | Broader attestation vector and trust-anchor coverage depth |
| `webauthn-server-core-jvm` | Beta | Registration/authentication service flow + rpId hash verification for both ceremonies + in-memory stores + finish-flow failure-path tests (expired challenge, origin mismatch, challenge replay, unknown credential, signature failure) + comprehensive persistence race tests (concurrent double-consume, sign-count propagation, replay protection) | Persistence integration scenarios with external stores |
| `webauthn-server-ktor` | Beta | Thin route adapters + tests | Operational hardening and sample-level integration depth |
| `webauthn-client-core` | Scaffold/Beta | Shared contracts and error model | Richer policy semantics + transport/runtime edge handling |
| `webauthn-client-android` | Scaffold/Beta | Credential Manager request serialization wired from model DTOs + deterministic cancellation/platform error mapping tests | Response parsing and full success-path propagation |
| `webauthn-client-ios` | Scaffold/Beta | NSError-to-PasskeyClientError mapping with unit coverage + AuthenticationServices scaffold/compile path | Delegate lifecycle handling and response parsing |
| `webauthn-network-ktor-client` | Production-leaning | Transport helper client + payload tests, Related Origins fetcher | Retry/error policy hardening |
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

- Platform client response parsing and success-path behavior validation
- L3 extension runtime hardening (PRF HMAC computation context hooks and richer authenticator interoperability vectors)

Resolved (COSE gap):

- COSE parsing is in a dedicated component (`JvmCoseParser`); support matrix documented in `webauthn-server-jvm-crypto/COSE_SUPPORT.md` (EC2 P-256, RSA supported; Ed25519/OKP unsupported). Unsupported/malformed keys fail deterministically; P1-006 conformance vectors added (malformed CBOR, unsupported key shapes, strict rejection). `CoseKeyParser.parsePublicKey` returns `CoseParseResult` (Success/Failure); Jca/Signum signature verifiers return `false` when decode or SPKI conversion fails (no raw-byte fallback).

## Current Quality Gates

Local:

- Fast advisory: `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
- Strict blocking: `tools/agent/quality-gate.sh --mode strict --scope changed --block true`

Docs trace requirements in strict mode:

- Spec trace: `spec-notes/webauthn-l3-validation-map.md` for validator/model semantic changes.
- Status trace: `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md` for core/security-critical changes.
