# WebAuthn Kotlin Multiplatform

Standards-first WebAuthn Level 3 foundation for Kotlin Multiplatform with modular artifacts for backend, Android, and iOS.

## Modules

- `webauthn-model`: protocol value objects and validation (no serialization deps)
- `webauthn-serialization-kotlinx`: wire DTOs and mappers
- `webauthn-core`: pure ceremony validation logic
- `webauthn-crypto-api`: crypto abstraction interfaces
- `webauthn-server-jvm-crypto`: JCA-based crypto primitives for backend
- `webauthn-server-core-jvm`: registration/authentication services + stores
- `webauthn-server-ktor`: optional Ktor adapters
- `webauthn-client-core`: shared client contracts
- `webauthn-client-android`: Android Credential Manager scaffold
- `webauthn-client-ios`: iOS AuthenticationServices scaffold
- `webauthn-network-ktor-client`: optional client transport helpers
- `webauthn-attestation-mds`: optional FIDO metadata trust source
- `platform:bom`: aligned dependency coordinates
- `samples:*`: backend/android/ios usage examples

## Status

This repository is currently a V1 scaffold with strict validation foundations, module boundaries, and service contracts in place. Some platform adapter and attestation paths are intentionally scaffolded for iterative hardening.

## Standards

- W3C WebAuthn Level 3
- RFC 4648 (base64url)
- RFC 8949 (CBOR)
- RFC 9052 / RFC 9053 (COSE)

See `spec-notes/` for implemented rule mapping.

## AI Harness

Repository AI steering is centralized in `docs/ai/STEERING.md`.

Quick start:

```bash
tools/agent/setup-hooks.sh
tools/agent/verify-harness-sync.sh
```

Common gate commands:

```bash
tools/agent/quality-gate.sh --mode fast --scope changed --block false
tools/agent/quality-gate.sh --mode strict --scope changed --block true
```

Related docs:

- `docs/ai/WORKFLOWS.md`
- `docs/ai/COST_POLICY.md`
- `docs/ai/SKILLS.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/ROADMAP.md`
