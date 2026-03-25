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

    /**
     * Validates registration extension IO coherence for currently supported extensions.
     *
     * Enforced checks:
     * - `largeBlob.support == REQUIRED` must be reflected as supported in outputs.
     * - `prf` request must yield corresponding PRF output metadata.
     */
    override fun validateRegistrationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        // W3C WebAuthn L3: §9.2.2. Large blob storage extension (largeBlob)
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

        // W3C WebAuthn L3: §9.2.1. HMAC Secret Extension (prf)
        // 2. PRF validation
        val prfInput = inputs?.prf
        if (prfInput != null) {
            val prfOutput = outputs?.prf
            if (prfOutput == null) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "extensions.prf",
                    message = "PRF extension was requested but no PRF output was returned",
                )
            } else if (prfOutput.enabled == false && prfInput.eval != null) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "extensions.prf.enabled",
                    message = "PRF was enabled in inputs but reported as disabled by authenticator",
                )
            }
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    /**
     * Validates authentication extension IO coherence for currently supported extensions.
     *
     * Enforced checks:
     * - requested PRF evaluation must return PRF results.
     * - a requested second PRF output must be present in results.
     */
    override fun validateAuthenticationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        // W3C WebAuthn L3: §9.2.1. HMAC Secret Extension (prf)
        // 1. PRF validation
        val prfInput = inputs?.prf
        if (prfInput?.eval != null || prfInput?.evalByCredential != null) {
            val prfResults = outputs?.prf?.results
            if (prfResults == null) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "extensions.prf.results",
                    message = "PRF evaluation was requested but no PRF results were returned",
                )
            } else {
                // Check if we expected two outputs but got one
                val requestedSecond = prfInput.eval?.second != null ||
                                     prfInput.evalByCredential?.values?.any { it.second != null } == true
                if (requestedSecond && prfResults.second == null) {
                    errors += WebAuthnValidationError.InvalidValue(
                        field = "extensions.prf.results.second",
                        message = "PRF evaluation requested two outputs but only one was returned",
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
