# webauthn-model

Audience: teams that want typed WebAuthn protocol models, validation wrappers, and immutable byte-domain types.

## What it provides

- WebAuthn protocol data classes for registration/authentication options and responses.
- Domain-safe wrappers for critical values (`RpId`, `Origin`, `Challenge`, `CredentialId`, `Base64UrlBytes`, fixed-size byte types).
- Shared `ValidationResult` and `WebAuthnValidationError` contracts used across validation and orchestration layers.
- Level 3 extension model types (`prf`, `largeBlob`, related origins).

```mermaid
flowchart LR
    Wire[Wire input<br/>JSON/CBOR/host values] --> Parse[Typed parsing<br/>Base64UrlBytes / RpId / Origin / Challenge]
    Parse --> Domain[Domain wrappers<br/>CredentialId / UserHandle / RpIdHash / Aaguid]
    Domain --> Protocol[Protocol models<br/>Creation/Request/Response objects]
    Protocol --> Result[ValidationResult&lt;T&gt;<br/>Valid or Invalid(errors)]
    Result --> Core[webauthn-core validators]
    Result --> Client[webauthn-client-* orchestration]
    Result --> Server[webauthn-server-* services]
```

## Typical integration scenario

A backend receives a typed transport DTO, validates user-controlled fields into model wrappers, and only then constructs `PublicKeyCredential*Options` or response models used by validation/services.

## How to use

Use parse APIs at trust boundaries and branch on `ValidationResult` before creating protocol objects.

```kotlin
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialDescriptor
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.RpId
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.ValidationResult

fun buildRequestOptions(
    challengeBytes: ByteArray,
    rpIdText: String,
    knownCredentialId: dev.webauthn.model.CredentialId,
): ValidationResult<PublicKeyCredentialRequestOptions> {
    val rpId = RpId.parse(rpIdText)
    return when (rpId) {
        is ValidationResult.Invalid -> rpId
        is ValidationResult.Valid -> {
            val options = PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(challengeBytes),
                rpId = rpId.value,
                allowCredentials = listOf(
                    PublicKeyCredentialDescriptor(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        id = knownCredentialId,
                    ),
                ),
                userVerification = UserVerificationRequirement.PREFERRED,
            )
            ValidationResult.Valid(options)
        }
    }
}
```

API notes:

- `parse(...)` is best for untrusted input and returns aggregated domain errors.
- `parseOrThrow(...)` is best for trusted config/bootstrap paths.
- `Challenge.fromBytes(...)` enforces minimum entropy length requirements.
- Keep values wrapped (`Base64UrlBytes`, `CredentialId`, etc.) instead of passing raw `ByteArray` between layers.

## Module boundaries

- Upstream from almost all modules: this is the protocol/value foundation.
- Consumed directly by `webauthn-core`, `webauthn-client-core`, and serialization/crypto/server modules.
- Independent of platform/network/server frameworks by design.

## Pitfalls and limits

- This module does not perform full ceremony verification (use `webauthn-core` and server crypto/services for that).
- It does not provide JSON/CBOR mapping by itself (use `webauthn-serialization-kotlinx` when needed).
- It does not hash RP IDs or verify signatures/attestation.

## Status

Production-leaning core contract module.
