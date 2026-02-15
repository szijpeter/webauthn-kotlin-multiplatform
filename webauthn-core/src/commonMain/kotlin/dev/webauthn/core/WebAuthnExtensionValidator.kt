package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.LargeBlobExtensionInput
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/**
 * Default implementation of extension validation logic.
 *
 * This validator checks normative requirements for L3 extensions like LargeBlob
 * and provides a hook for other extensions.
 */
@ExperimentalWebAuthnL3Api
public object WebAuthnExtensionValidator : WebAuthnExtensionHook {

    override fun validateRegistrationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        // 1. LargeBlob validation
        if (inputs?.largeBlob?.support == LargeBlobExtensionInput.LargeBlobSupport.REQUIRED) {
            val supported = outputs?.largeBlob?.supported ?: false
            if (!supported) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "extensions.largeBlob",
                    message = "LargeBlob support is required but not provided or supported by the authenticator"
                )
            }
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    override fun validateAuthenticationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        // For Authentication, we mostly expect results if we sent inputs.
        // Normative L3 doesn't typically "fail" purely based on output absence unless it's an RP policy.

        return if (errors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(errors)
        }
    }
}
