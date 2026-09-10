# webauthn-protocol

Audience: integrators and adapters that need strict WebAuthn binary protocol interpretation without selecting a JSON or CBOR object codec.

## What it provides

- Parsing of authenticator-data bytes into typed WebAuthn model values
- Structural extraction of `authData` from a CBOR attestation object
- Validation errors expressed through the neutral `webauthn-model` result types

## When to use

Use this module at the boundary between untrusted raw credential bytes and clean
WebAuthn protocol models. It depends only on `webauthn-model` and
`webauthn-cbor-core`; it does not require `kotlinx.serialization`.

## How to use

<!-- doc-example: id=core-webauthn-protocol-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/ProtocolExample.kt#protocol-authenticator-data -->
```kotlin
fun parseAuthenticatorData(bytes: ByteArray): ValidationResult<ParsedAuthenticatorData> {
    return WebAuthnProtocolParser.parseAuthenticatorData(bytes)
}
```

For registration responses, call `extractAuthenticatorData` on the raw
attestation object before parsing the returned immutable `Base64UrlBytes` value.
The caller remains responsible for ceremony policy and attestation verification.

## How it fits in the system

<!-- diagram: core-webauthn-protocol-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-protocol-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/core-webauthn-protocol-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-protocol-readme-1-desktop-dark.svg">
  <img alt="protocol · How it fits in the system. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/core-webauthn-protocol-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: protocol · How it fits in the system</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-protocol; webauthn-cbor-core; webauthn-model; webauthn-json-kotlinx.</p>
<p>1. webauthn-protocol → webauthn-cbor-core.</p>
<p>2. webauthn-protocol → webauthn-model.</p>
<p>3. webauthn-json-kotlinx → webauthn-protocol.</p>
</details>
<!-- /diagram -->

Arrows point from a consuming module to its direct dependency. JSON implementations may use the
protocol parser, while the parser itself remains independent of any serialization implementation.

## Status

Beta, public protocol interpretation module.
