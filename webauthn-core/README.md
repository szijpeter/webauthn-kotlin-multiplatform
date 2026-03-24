# webauthn-core

Audience: teams validating WebAuthn ceremonies without committing to a specific server framework.

## What it validates

- Client data checks (`type`, `challenge`, `origin`, related origins).
- Authenticator data checks (UP/UV flags, backup flags, signature counter progression).
- Allowed-credential checks for authentication `allowCredentials` handling.
- Extension hook integration points for optional Level 3 extension verification.

```mermaid
flowchart TD
    Start[Typed ceremony input<br/>RegistrationValidationInput / AuthenticationValidationInput] --> ClientData[validateClientData]
    ClientData --> AuthData[validateAuthenticatorData]
    AuthData --> AllowCred[requireAllowedCredential]
    AllowCred --> Hook[WebAuthnExtensionHook (optional)]
    Hook --> Result[ValidationResult output]
    Result --> Crypto[Crypto verification layer
signature + attestation]
```

## Real-world flow placement

Use `webauthn-core` after parsing transport payloads into model types and before cryptographic verification and persistence updates.

## How to use

A typical authentication finish path combines core checks with credential allow-list and server-owned counters.

```kotlin
import dev.webauthn.core.AuthenticationValidationInput
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.model.ValidationResult

fun validateAssertion(
    input: AuthenticationValidationInput,
    allowedCredentialIds: Set<dev.webauthn.model.CredentialId>,
): ValidationResult<Long> {
    val validation = WebAuthnCoreValidator.validateAuthentication(input)
    if (validation is ValidationResult.Invalid) {
        return ValidationResult.Invalid(validation.errors)
    }
    val output = (validation as ValidationResult.Valid).value

    val allowResult = WebAuthnCoreValidator.requireAllowedCredential(
        response = input.response,
        allowedCredentialIds = allowedCredentialIds,
    )
    return when (allowResult) {
        is ValidationResult.Valid -> ValidationResult.Valid(output.signCount)
        is ValidationResult.Invalid -> ValidationResult.Invalid(allowResult.errors)
    }
}
```

Important API details:

- `validateRegistration(...)` and `validateAuthentication(...)` return typed outputs with credential id, sign count, and extension outputs.
- `allowedOrigins` supports related-origin acceptance only when explicitly requested.
- `previousSignCount` must come from server-trusted credential state.
- This module intentionally does not verify signatures/attestation; run crypto checks after core validation.

## Extension and origin handling

- Use `WebAuthnExtensionValidator` for default PRF/LargeBlob validation behavior.
- Use `OriginMetadataProvider` in higher layers when related origins must be fetched dynamically.

## Limits

- No persistence: challenge lifecycle and credential storage are caller-owned.
- No transport mapping: parsing/JSON/CBOR belongs to other modules.
- No crypto backend behavior: handled by `webauthn-crypto-api` implementations.

## Status

Production-leaning validation engine.
