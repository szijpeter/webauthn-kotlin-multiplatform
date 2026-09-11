# webauthn-model

Audience: teams that need typed WebAuthn values and protocol models as the shared contract between transport, validation, and service layers.

## What it provides

- Domain wrappers for protocol-critical values (`RpId`, `Origin`, `Challenge`, `CredentialId`, `Base64UrlBytes`, fixed-size byte types).
- Typed protocol models for registration/authentication options and responses.
- Shared `ValidationResult` and `WebAuthnValidationError` contracts used across client and server orchestration.
- L3 extension model types (`prf`, `largeBlob`, related origins).

On JVM, `LargeBlobExtensionInput` and `LargeBlobExtensionOutput` expose public no-argument constructors with all properties set to `null`. Kotlin 2.4.20 generates these constructors for their defaulted parameters, including the nullable `Base64UrlBytes` value-class parameters.

<!-- diagram: core-webauthn-model-readme-1 -->
<a href="../../docs/diagrams/assets/core-webauthn-model-readme-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-model-readme-1-desktop-dark.svg">
  <img alt="model · What it provides. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/core-webauthn-model-readme-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: model · What it provides</summary>
<p>Phone view: <a href="../../docs/diagrams/assets/core-webauthn-model-readme-1-mobile-light.svg">light</a> · <a href="../../docs/diagrams/assets/core-webauthn-model-readme-1-mobile-dark.svg">dark</a>.</p>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: Untrusted input — HTTP JSON / mobile payload; parse(...) boundary — RpId / Origin / CredentialId / Base64UrlBytes; Typed wrappers; Protocol models — PublicKeyCredential*Options / *Response; ValidationResult — Valid or Invalid (errors); webauthn-core; webauthn-client-* modules; webauthn-server-* modules.</p>
<p>1. Untrusted input HTTP JSON / mobile payload → parse(...) boundary RpId / Origin / CredentialId / Base64UrlBytes.</p>
<p>2. parse(...) boundary RpId / Origin / CredentialId / Base64UrlBytes → Typed wrappers.</p>
<p>3. Typed wrappers → Protocol models PublicKeyCredential*Options / *Response.</p>
<p>4. Protocol models PublicKeyCredential*Options / *Response → ValidationResult Valid or Invalid (errors).</p>
<p>5. ValidationResult Valid or Invalid (errors) → webauthn-core.</p>
<p>6. ValidationResult Valid or Invalid (errors) → webauthn-client-* modules.</p>
<p>7. ValidationResult Valid or Invalid (errors) → webauthn-server-* modules.</p>
</details>
<!-- /diagram -->

## Typical usage boundary

Use model parsing at every trust boundary (HTTP request body, local storage restore, deep-link input, remote config). Keep wrappers intact between layers instead of converting back to raw strings/bytes.

## How to use

This example shows a sign-in options builder that validates untrusted RP input and only creates typed protocol options on success.

<!-- doc-example: id=core-webauthn-model-readme-kotlin-1; owner=source; verify=unit; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/ModelExample.kt#model-request-options -->
```kotlin
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialDescriptor
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.RpId
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.ValidationResult

fun buildSignInOptions(
    challengeBytes: ByteArray,
    rpIdFromRequest: String,
    storedCredentialId: String,
): ValidationResult<PublicKeyCredentialRequestOptions> {
    val rpId = RpId.parse(rpIdFromRequest)
    val credentialId = CredentialId.parse(storedCredentialId)

    if (rpId is ValidationResult.Invalid) return rpId
    if (credentialId is ValidationResult.Invalid) return credentialId

    val options = PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(challengeBytes),
        rpId = (rpId as ValidationResult.Valid).value,
        allowCredentials = [
            PublicKeyCredentialDescriptor(
                type = PublicKeyCredentialType.PUBLIC_KEY,
                id = (credentialId as ValidationResult.Valid).value,
            ),
        ],
        userVerification = UserVerificationRequirement.PREFERRED,
    )
    return ValidationResult.Valid(options)
}
```

API notes:

- Prefer `parse(...)` for untrusted values; it preserves structured validation errors.
- Use `parseOrThrow(...)` only for trusted bootstrap/config paths.
- `Challenge.fromBytes(...)` enforces minimum challenge length.
- Wrapper types (`CredentialId`, `RpIdHash`, `Aaguid`, etc.) are the canonical cross-module value format.
- Kotlin consumers that enable `-Xreturn-value-checker=check` are warned when marked parsing, conversion, or `ValidationResult` helper results are ignored.
- Standard extensions are iterable via `WebAuthnExtension.Standard.entries` (and `WebAuthnExtension.standardExtensions`).
- `WebAuthnExtension.Custom` rejects reserved standard extension identifiers (for example `prf` and `largeBlob`) to prevent collisions.
- `RawRegistrationResponse` and `RawAuthenticationResponse` preserve untrusted platform/transport output. Parse and validate them before treating a result as a ceremony response.

## Pitfalls and limits

- No full ceremony verification (use `webauthn-core` + server crypto/services).
- No JSON/CBOR mapping by itself (use `webauthn-json-kotlinx` when needed).
- No RP hash/signature/attestation verification logic.

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta public compatibility, with production-leaning internal implementation maturity. This remains a
foundational contract module, and the pre-1.0 compatibility policy still applies to consumers.
