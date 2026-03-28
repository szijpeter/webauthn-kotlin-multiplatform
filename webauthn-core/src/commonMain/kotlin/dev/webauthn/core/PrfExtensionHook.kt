package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/**
 * Extension hook that validates PRF (HMAC Secret) extension IO coherence.
 *
 * W3C WebAuthn L3: §9.2.1. HMAC Secret Extension (prf)
 *
 * Use this standalone hook to add PRF validation to a custom extension hook pipeline,
 * or rely on [WebAuthnExtensionValidator] which includes it by default.
 */
@ExperimentalWebAuthnL3Api
public object PrfExtensionHook : WebAuthnExtensionHook {

    /**
     * Registration: verifies that a requested PRF extension yields output metadata
     * and that the authenticator does not report PRF as disabled when eval was provided.
     */
    override fun validateRegistrationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

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
     * Authentication: verifies that requested PRF evaluation returns results and
     * that a requested second output is present.
     */
    override fun validateAuthenticationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val prfInput = inputs?.prf
        if (prfInput?.eval != null || prfInput?.evalByCredential != null) {
            val prfResults = outputs?.prf?.results
            if (prfResults == null) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "extensions.prf.results",
                    message = "PRF evaluation was requested but no PRF results were returned",
                )
            } else {
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
