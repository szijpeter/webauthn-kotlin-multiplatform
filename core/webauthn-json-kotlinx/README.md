# webauthn-json-kotlinx

Serialization and mapping helpers between wire DTOs and typed WebAuthn domain models.

## What it provides

- `WebAuthnDtoMapper` mapping between DTO and `webauthn-model`
- `kotlinx.serialization`-based DTO support
- `clientDataJSON` parsing and DTO conversion; binary protocol interpretation is provided by `webauthn-protocol`

## When to use

Use this when your boundary is JSON/CBOR but your application code should stay typed.

## How to use

<!-- doc-example: id=core-webauthn-json-kotlinx-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/SerializationExample.kt#serialization-mapper -->
```kotlin
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.WebAuthnDtoMapper

fun decodeRequestOptions(
    dto: PublicKeyCredentialRequestOptionsDto,
): ValidationResult<PublicKeyCredentialRequestOptions> {
    return WebAuthnDtoMapper.toModel(dto)
}

fun encodeRequestOptions(
    model: PublicKeyCredentialRequestOptions,
): PublicKeyCredentialRequestOptionsDto {
    return WebAuthnDtoMapper.fromModel(model)
}
```

Real-world scenario: parse backend JSON into typed model objects, run validation/business logic, then map back to DTOs for responses.

## How it fits

<!-- diagram: core-webauthn-json-kotlinx-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-json-kotlinx-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/core-webauthn-json-kotlinx-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-json-kotlinx-readme-1-desktop-dark.svg">
  <img alt="json-kotlinx · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/core-webauthn-json-kotlinx-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: json-kotlinx · How it fits</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: Wire DTOs (JSON or CBOR); WebAuthnDtoMapper; webauthn-model; webauthn-core.</p>
<p>1. Wire DTOs (JSON or CBOR) → WebAuthnDtoMapper.</p>
<p>2. WebAuthnDtoMapper → webauthn-model.</p>
<p>3. webauthn-core → webauthn-model.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- Mapper validation is strict by design; malformed wire data should be handled as untrusted input.
- Use `webauthn-protocol` directly when an adapter needs binary authenticator-data or attestation-object interpretation without selecting this codec.
- Canonical response DTO mapping emits standards-shaped WebAuthn response JSON fields (`type = "public-key"` and `clientExtensionResults`, including empty extension objects when no outputs are present).
- Use `WebAuthnDtoMapper.parseCollectedClientData(...)` to derive ceremony `type`, `challenge`, and `origin` from the credential response's signed `clientDataJSON`; never treat duplicate transport fields as authoritative.
- `residentKey` is the authoritative creation-options field; legacy `requireResidentKey` payloads are now rejected explicitly instead of being mapped.
- Credential descriptors in `excludeCredentials`/`allowCredentials` must use `type = "public-key"`; mismatched types are rejected with explicit validation errors.
- `allowCredentials: null` is accepted only as a compatibility decode shim and normalized to an empty list; canonical JSON should still treat `allowCredentials` as an optional sequence (not `null`).
- Keep model and mapper versions aligned (BOM recommended).

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta, strict mapper validation and signed client-data parsing.
