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

```mermaid
flowchart TB
    subgraph L1[Layer 1: Protocol Model]
        MODEL[webauthn-model]
    end

    subgraph L2[Layer 2: Validation and Serialization]
        CORE[webauthn-core]
        SER[webauthn-serialization-kotlinx]
    end

    subgraph L3[Layer 3: Crypto]
        API[webauthn-crypto-api]
        JVMCRYPTO[webauthn-server-jvm-crypto]
    end

    subgraph L4[Layer 4: Server]
        SVC[webauthn-server-core-jvm]
        KTOR[webauthn-server-ktor]
        STORE[webauthn-server-store-exposed]
        MDS[webauthn-attestation-mds]
    end

    subgraph L5[Layer 5: Client]
        CCORE[webauthn-client-core]
        CJSON[webauthn-client-json-core]
        CANDROID[webauthn-client-android]
        CIOS[webauthn-client-ios]
        CCOMPOSE[webauthn-client-compose]
        CPRF[webauthn-client-prf-crypto]
        NET[webauthn-network-ktor-client]
    end

    MODEL --> CORE
    MODEL --> SER
    CORE --> API
    JVMCRYPTO --> API
    CORE --> SVC
    SER --> SVC
    SVC --> KTOR
    SVC --> STORE
    MDS --> API

    MODEL --> CCORE
    CCORE --> CJSON
    CCORE --> CANDROID
    CCORE --> CIOS
    CCORE --> CCOMPOSE
    CCORE --> CPRF
    CORE --> NET
    SER --> NET
    CCORE --> NET
```

`webauthn-model` has no dependencies on the rest of the codebase.

## Backend runtime

V1 backend target is Kotlin/JVM. Core ceremony services are in `webauthn-server-core-jvm` and stay framework-agnostic.

## Framework adapters

Ktor adapter modules are intentionally thin wrappers around core services.

`webauthn-network-ktor-client` keeps `io.ktor.client.HttpClient` in its public contract, so the module publishes `ktor-client-core` as an API dependency for consumer compile compatibility while leaving engine selection to host apps.

## Experimental Level 3 API surface

Extension APIs that may evolve are marked with `@ExperimentalWebAuthnL3Api`.
