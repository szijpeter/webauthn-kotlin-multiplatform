# Architecture Overview

## Goals

- Standards-first WebAuthn L3 behavior.
- Strict separation of concerns:
  - model and validation
  - protocol/core logic
  - crypto implementation
  - transport and platform adapters
- Dependency minimization with optional feature modules.

## Layering

1. `webauthn-model`
2. `webauthn-serialization-kotlinx`
3. `webauthn-core`
4. `webauthn-crypto-api`
5. backend/client/platform modules

`webauthn-model` has no dependencies on the rest of the codebase.

## Backend runtime

V1 backend target is Kotlin/JVM. Core ceremony services are in `webauthn-server-core-jvm` and stay framework-agnostic.

## Framework adapters

Ktor adapter modules are intentionally thin wrappers around core services.

## Experimental Level 3 API surface

Extension APIs that may evolve are marked with `@ExperimentalWebAuthnL3Api`.
