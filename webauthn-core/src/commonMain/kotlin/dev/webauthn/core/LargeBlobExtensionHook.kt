package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.LargeBlobExtensionInput
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.model.WebAuthnValidationError

/**
 * Extension hook that validates Large Blob extension IO coherence.
 *
 * W3C WebAuthn L3: §9.2.2. Large blob storage extension (largeBlob)
 *
 * Use this standalone hook to add Large Blob validation to a custom extension hook pipeline,
 * or rely on [WebAuthnExtensionValidator] which includes it by default.
 */
@ExperimentalWebAuthnL3Api
public object LargeBlobExtensionHook : TargetedExtensionHook {

    override val extension: WebAuthnExtension = WebAuthnExtension.LargeBlob

    /**
     * Registration: verifies that `largeBlob.support == REQUIRED` is reflected
     * as supported in outputs.
     */
    override fun validateRegistrationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit> {
        if (inputs?.largeBlob?.support == LargeBlobExtensionInput.LargeBlobSupport.REQUIRED) {
            val supported = outputs?.largeBlob?.supported ?: false
            if (!supported) {
                return ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidValue(
                            field = "extensions.largeBlob",
                            message = "LargeBlob support is required but not provided " +
                                "or supported by the authenticator",
                        ),
                    ),
                )
            }
        }
        return ValidationResult.Valid(Unit)
    }

    /**
     * Authentication: no normative large blob authentication checks are currently enforced.
     */
    override fun validateAuthenticationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit> = ValidationResult.Valid(Unit)
}
