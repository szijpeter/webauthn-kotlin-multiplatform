# Implementation Status

This document tracks what is implemented today and the current maturity by module.

Last updated: 2026-02-15

## Status Legend

- `Production-leaning`: core behavior implemented and tested; hardening continues.
- `Beta`: usable for development/testing; behavior surface still evolving.
- `Scaffold`: structural/API foundation in place; significant implementation remains.

## Overall Snapshot

- Protocol model and core validation baselines are implemented with strict negative-path tests.
- JVM server flow is implemented with ceremony orchestration and smoke tests.
- Platform clients (Android/iOS) and attestation trust paths remain hardening-focused.
- CI lanes cover JVM checks, Android assemble, and iOS compile.

## Module Maturity

| Module | Maturity | Implemented | Gaps / Risks |
|---|---|---|---|
| `webauthn-model` | Production-leaning | Typed protocol models, strict base64url behavior, value semantics tests | Continued edge-case coverage for uncommon protocol combinations |
| `webauthn-core` | Production-leaning | Core ceremony validation (type/challenge/origin/rpIdHash/UP/UV-policy/BE-BS-consistency/signCount/allowCredentials), broad negative-path tests | Additional L3 extensions hardening |
| `webauthn-serialization-kotlinx` | Beta | DTO mapping + authData parsing, round-trip tests | Deeper COSE/CBOR vector coverage |
| `webauthn-crypto-api` | Beta | Abstraction interfaces in place | Additional implementations and cross-provider behavior parity |
| `webauthn-server-jvm-crypto` | Beta | JCA/JCE crypto baseline + `none`/`packed`/`android-key` trust-path + `tpm`/`apple` + `android-safetynet` scaffold + dispatcher integration | Additional attestation formats (none missing?), `android-key` depth |
| `webauthn-server-core-jvm` | Beta | Registration/authentication service flow + rpId hash verification for both ceremonies + in-memory stores + finish-flow failure-path tests (expired challenge, origin mismatch, challenge replay, unknown credential, signature failure) + persistence race tests (double-consume, overwrite, sign-count propagation) | Persistence integration scenarios with external stores |
| `webauthn-server-ktor` | Beta | Thin route adapters + tests | Operational hardening and sample-level integration depth |
| `webauthn-client-core` | Scaffold/Beta | Shared contracts and error model | Richer policy semantics + transport/runtime edge handling |
| `webauthn-client-android` | Scaffold/Beta | Credential Manager integration scaffold and sample buildability | Runtime passkey behavior hardening across device/API variations |
| `webauthn-client-ios` | Scaffold/Beta | AuthenticationServices scaffold and compile path | Runtime behavior hardening + delegate lifecycle/error handling |
| `webauthn-network-ktor-client` | Beta | Transport helper client + payload tests | Retry/error policy hardening |
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

- remaining attestation statement formats (`tpm`, `android-key`, `android-safetynet`, `apple`)
- packed attestation AAGUID extension validation
- L3 extension-specific checks (PRF, `largeBlob`, Related Origins)

## Current Quality Gates

Local:

- Fast advisory: `tools/agent/quality-gate.sh --mode fast --scope changed --block false`
- Strict blocking: `tools/agent/quality-gate.sh --mode strict --scope changed --block true`

Docs trace requirements in strict mode:

- Spec trace: `spec-notes/webauthn-l3-validation-map.md` for validator/model semantic changes.
- Status trace: `docs/IMPLEMENTATION_STATUS.md` and/or `docs/ROADMAP.md` for core/security-critical changes.
