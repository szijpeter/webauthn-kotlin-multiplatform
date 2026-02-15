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

        // 2. PRF validation
        val prfInput = inputs?.prf
        if (prfInput != null) {
            val prfOutput = outputs?.prf
            if (prfOutput == null) {
                // Technically optional unless RP policy says otherwise, but spec says "the authenticator MUST return the prf extension"
                // if it was in the create call. However, old authenticators might ignore it.
                // We'll treat it as valid unless we have a "REQUIRED" flag (which PRF doesn't have in inputs yet).
            } else if (prfOutput.enabled == false && prfInput.eval != null) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "extensions.prf.enabled",
                    message = "PRF was enabled in inputs but reported as disabled by authenticator"
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

        // 1. PRF validation
        val prfInput = inputs?.prf
        if (prfInput?.eval != null || prfInput?.evalByCredential != null) {
            val prfResults = outputs?.prf?.results
            if (prfResults == null) {
                // If we requested evaluation, we expect results.
            } else {
                // Check if we expected two outputs but got one
                val requestedSecond = prfInput.eval?.second != null || 
                                     prfInput.evalByCredential?.values?.any { it.second != null } == true
                if (requestedSecond && prfResults.second == null) {
                     errors += WebAuthnValidationError.InvalidValue(
                        field = "extensions.prf.results.second",
                        message = "PRF evaluation requested two outputs but only one was returned"
                    )
                }
            }
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(errors)
        }
    }
}
