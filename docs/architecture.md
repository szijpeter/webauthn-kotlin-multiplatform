# Architecture

## Design goals

- Standards-first WebAuthn L3 behavior.
- Strict separation between protocol model, shared foundation, cryptography, client orchestration, and JVM server services.
- Thin platform and transport adapters with optional features kept out of the core path.
- Architecture documentation that explains both repository structure and real application adoption.

## How to read the diagrams

The repository overview shows logical responsibility relationships. The focused
module diagrams show direct internal Gradle project dependencies for a selected
slice. In module diagrams, arrows point from the consumer to its dependency.

External Maven dependencies are omitted. Optional adapters are labelled
explicitly. The diagrams are intentionally curated rather than exhaustive.

## Repository overview

The [repository overview in the root README](../README.md#repository-structure)
shows the five logical responsibility areas. It intentionally omits individual
projects, samples, documentation utilities, and transitive dependencies.

## Reference integration

This view shows where the library is used in a typical passkey application. The
SDK is represented inside the client and backend descriptions rather than as a
separate runtime system.

<!-- doc-example: id=docs-architecture-mermaid-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart LR
    USER([End user])

    subgraph APPLICATION["Reference passkey application"]
        CLIENT["Client application<br/>webauthn-client-core plus an Android or iOS bridge"]
        BACKEND["Relying-party backend<br/>webauthn-server-core-jvm plus optional adapters"]
        STORE[("Credential store")]
    end

    PLATFORM["Platform passkey API<br/>Credential Manager or AuthenticationServices"]
    MDS["Attestation metadata service<br/>(optional)"]

    USER -->|initiates registration or authentication| CLIENT
    CLIENT -->|requests ceremony options and submits credential responses| BACKEND; BACKEND -->|returns ceremony options and verification results| CLIENT
    CLIENT -->|invokes the passkey ceremony| PLATFORM
    BACKEND -->|stores registered credentials| STORE
    BACKEND -. optionally obtains attestation metadata .-> MDS
```

## Shared foundation

The shared foundation keeps protocol contracts, validation, serialization,
runtime helpers, and cryptographic contracts separated.

<!-- doc-example: id=docs-architecture-mermaid-2; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart TB
    CRYPTO_API["webauthn-crypto-api<br/>Kotlin/JVM"]
    CORE["webauthn-core"]
    SERIALIZATION["webauthn-serialization-kotlinx"]
    PROTOCOL["webauthn-protocol"]
    CBOR["webauthn-cbor-core"]
    MODEL["webauthn-model"]
    RUNTIME["webauthn-runtime-core<br/>No internal project dependencies"]

    CRYPTO_API --> CORE
    CRYPTO_API --> MODEL
    CORE --> MODEL
    SERIALIZATION --> PROTOCOL
    PROTOCOL --> MODEL
    PROTOCOL --> CBOR
```

The isolated runtime node is intentional. It communicates that this module has
no internal project dependencies without inventing an edge.

## Client stack

`webauthn-client-core` owns shared orchestration. JSON, Android, iOS, Compose,
PRF, and network modules build around that shared boundary.

<!-- doc-example: id=docs-architecture-mermaid-3; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart TB
    COMPOSE["webauthn-client-compose"]
    ANDROID["webauthn-client-android"]
    IOS["webauthn-client-ios"]
    JSON["webauthn-client-json-core"]
    PRF["webauthn-client-prf-crypto<br/>(optional)"]
    NETWORK["webauthn-network-ktor-client<br/>(optional)"]
    CLIENT_CORE["webauthn-client-core"]
    FOUNDATION["Shared foundation"]
    MODEL["Protocol model"]

    COMPOSE --> CLIENT_CORE
    COMPOSE --> ANDROID
    COMPOSE --> IOS

    ANDROID --> CLIENT_CORE
    ANDROID --> JSON

    IOS --> CLIENT_CORE
    IOS --> JSON

    JSON --> CLIENT_CORE
    JSON --> FOUNDATION

    PRF --> CLIENT_CORE
    PRF --> FOUNDATION

    NETWORK --> CLIENT_CORE
    NETWORK --> FOUNDATION

    CLIENT_CORE --> FOUNDATION
    CLIENT_CORE --> MODEL
```

External libraries, platform APIs, source-set details, and samples are
intentionally omitted from this module dependency view.

The view focuses on direct project dependencies among published client modules.
Platform adapters remain separate from shared orchestration, and optional
features remain outside the core path.

For platform-specific behavior, see the reference integration and module
READMEs. For runnable adoption paths, see the sample documentation.



## JVM server stack

The server core remains framework-agnostic. Ktor, Exposed, and metadata support
are optional adapters around the core and cryptographic boundaries.

<!-- doc-example: id=docs-architecture-mermaid-4; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart TB
    KTOR["webauthn-server-ktor<br/>(optional adapter)"]
    STORE["webauthn-server-store-exposed<br/>(optional adapter)"]
    MDS["webauthn-attestation-mds<br/>(optional adapter)"]
    SERVER_CORE["webauthn-server-core-jvm"]
    JVM_CRYPTO["webauthn-server-jvm-crypto"]
    FOUNDATION["Shared foundation"]
    CRYPTO["Cryptography boundary"]

    KTOR --> SERVER_CORE

    STORE --> SERVER_CORE
    STORE --> FOUNDATION
    STORE --> CRYPTO

    MDS --> CRYPTO

    SERVER_CORE --> FOUNDATION
    SERVER_CORE --> CRYPTO

    JVM_CRYPTO --> FOUNDATION
    JVM_CRYPTO --> CRYPTO
```

## Distribution and samples

| Project | Role |
| --- | --- |
| `platform:bom` | Aligns versions across the published WebAuthn artifacts as `webauthn-bom`. |
| `platform:constraints` | Internal dependency constraints used by the build. It is not published. |
| `sample:*` | Runnable backend, client, Android, iOS, Compose, and CLI examples. Samples are not published runtime libraries. |
| `documentation:*` | Documentation example and verification tooling. These projects are not part of the published SDK surface. |

The published modules remain grouped under `core/`, `client/`, and `server/` by
responsibility. Distribution projects and samples are intentionally omitted
from the overview because they explain packaging and adoption rather than the
reusable library architecture.

## Dependency rules

- `webauthn-model` remains independent of the rest of the repository.
- `webauthn-protocol` interprets raw WebAuthn binary data using only the model and strict CBOR scanner; codecs depend on it rather than owning protocol parsing.
- `webauthn-client-core` owns shared client business logic; Android and iOS modules remain platform bridges.
- `webauthn-server-core-jvm` remains framework-agnostic; Ktor and Exposed are adapters.
- `webauthn-crypto-api` stays vendor-neutral; implementations belong behind the crypto boundary.
- Optional adapters must not become hidden prerequisites of core modules.
- Direct project dependencies shown here must be checked against the owning `build.gradle.kts` whenever the module graph changes.

## Diagram maintenance

Architecture diagrams are maintained directly as Mermaid blocks beside their
supporting prose.

Keep each diagram focused on one concern. Prefer a small curated view over a
complete repository dependency graph. Module dependency arrows point from the
consumer to its dependency, and optional modules must be labelled explicitly.

When changing a diagram:

1. Check direct project dependencies against the relevant `build.gradle.kts` files.
2. Run `./gradlew docsUpdate docsCheck --stacktrace`.
3. Run `tools/agent/quality-gate.sh --mode strict --scope changed --block true`.
4. Inspect the rendered diagram on GitHub for readability and edge crossings.
