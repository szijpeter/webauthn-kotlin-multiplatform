# webauthn-cbor-core

Audience: maintainers and advanced integrators needing strict CBOR byte-scanning primitives shared by parser modules.

## What it provides

- Shared strict CBOR byte-scanning helpers
- Support utilities reused by serialization and JVM crypto modules

## When to use

Use this module when a parser/validator needs low-level strict CBOR traversal utilities (header/length reads, item skipping, typed value extraction) without depending on higher-level DTO mappers.

## How it fits in the system

<!-- diagram: core-webauthn-cbor-core-readme-1 -->
<a href="../../docs/diagrams/assets/core-webauthn-cbor-core-readme-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-cbor-core-readme-1-desktop-dark.svg">
  <img alt="cbor-core · How it fits in the system. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/core-webauthn-cbor-core-readme-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: cbor-core · How it fits in the system</summary>
<p>Phone view: <a href="../../docs/diagrams/assets/core-webauthn-cbor-core-readme-1-mobile-light.svg">light</a> · <a href="../../docs/diagrams/assets/core-webauthn-cbor-core-readme-1-mobile-dark.svg">dark</a>.</p>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-cbor-core; webauthn-json-kotlinx; webauthn-server-jvm-crypto.</p>
<p>1. webauthn-cbor-core → webauthn-json-kotlinx.</p>
<p>2. webauthn-cbor-core → webauthn-server-jvm-crypto.</p>
</details>
<!-- /diagram -->

## Stability expectations

- APIs are public and intended for reuse by parser modules.
- Semantics remain strict by design (minimal-encoding rejection and overflow-safe bounds checks).

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta, shared CBOR parser primitive module.
