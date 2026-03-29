package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/**
 * Aggregates multiple [WebAuthnExtensionHook] implementations and collects all validation
 * errors without short-circuiting.
 *
 * This follows the Composite pattern to let consumers assemble extension validation
 * pipelines by composition rather than inheritance.
 *
 * ```kotlin
 * val hooks = CompositeExtensionHook(listOf(PrfExtensionHook, LargeBlobExtensionHook))
 * val result = hooks.validateRegistrationExtensions(inputs, outputs)
 * ```
 */
@ExperimentalWebAuthnL3Api
public class CompositeExtensionHook(
    hooks: List<WebAuthnExtensionHook>,
) : WebAuthnExtensionHook {
    
    private val hooks: List<WebAuthnExtensionHook> = hooks.toList()

    override fun validateRegistrationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit> = aggregate { it.validateRegistrationExtensions(inputs, outputs) }

    override fun validateAuthenticationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit> = aggregate { it.validateAuthenticationExtensions(inputs, outputs) }

    private fun aggregate(
        validate: (WebAuthnExtensionHook) -> ValidationResult<Unit>,
    ): ValidationResult<Unit> {
        val allErrors = mutableListOf<WebAuthnValidationError>()
        for (hook in hooks) {
            when (val result = validate(hook)) {
                is ValidationResult.Invalid -> allErrors.addAll(result.errors)
                is ValidationResult.Valid -> Unit
            }
        }
        return if (allErrors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(allErrors)
        }
    }
}
