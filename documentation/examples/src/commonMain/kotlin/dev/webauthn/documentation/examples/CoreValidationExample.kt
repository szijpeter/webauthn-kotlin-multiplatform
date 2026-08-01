package dev.webauthn.documentation.examples

// docs-region core-validation
import dev.webauthn.core.AuthenticationValidationInput
import dev.webauthn.core.AuthenticationValidationOutput
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.core.WebAuthnExtensionHook
import dev.webauthn.core.WebAuthnExtensionValidator
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.ValidationResult

/**
 * Chains core authentication checks, then requires cryptographic signature
 * verification before returning a successful finish result.
 *
 * Core validation alone is not enough to accept an assertion. Callers must
 * supply a [verifySignature] implementation (for example JVM crypto) that
 * succeeds before [ValidationResult.Valid] is returned.
 */
@OptIn(ExperimentalWebAuthnL3Api::class)
suspend fun validateAssertionForFinish(
    input: AuthenticationValidationInput,
    allowedCredentialIds: Set<CredentialId>,
    verifySignature: suspend (AuthenticationValidationOutput) -> ValidationResult<Unit>,
    extensionHook: WebAuthnExtensionHook = WebAuthnExtensionValidator,
): ValidationResult<Long> {
    val core = WebAuthnCoreValidator.validateAuthentication(input)
    if (core is ValidationResult.Invalid) return core

    val output = (core as ValidationResult.Valid).value

    val allow = WebAuthnCoreValidator.requireAllowedCredential(
        response = input.response,
        allowedCredentialIds = allowedCredentialIds,
    )
    if (allow is ValidationResult.Invalid) return allow

    val ext = extensionHook.validateAuthenticationExtensions(
        inputs = input.options.extensions,
        outputs = output.extensions,
    )
    if (ext is ValidationResult.Invalid) return ext

    val signature = verifySignature(output)
    if (signature is ValidationResult.Invalid) return signature

    // Persist output.signCount only after signature verification succeeds.
    return ValidationResult.Valid(output.signCount)
}
// docs-endregion core-validation
