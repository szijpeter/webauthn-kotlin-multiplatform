package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.LargeBlobExtensionInput
import dev.webauthn.model.LargeBlobExtensionOutput
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertTrue

@OptIn(ExperimentalWebAuthnL3Api::class)
class WebAuthnExtensionValidatorTest {

    @Test
    fun registrationFailsIfLargeBlobRequiredButNotSupported() {
        val inputs = AuthenticationExtensionsClientInputs(
            largeBlob = LargeBlobExtensionInput(support = LargeBlobExtensionInput.LargeBlobSupport.REQUIRED)
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            largeBlob = LargeBlobExtensionOutput(supported = false)
        )

        val result = WebAuthnExtensionValidator.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationPassesIfLargeBlobRequiredAndSupported() {
        val inputs = AuthenticationExtensionsClientInputs(
            largeBlob = LargeBlobExtensionInput(support = LargeBlobExtensionInput.LargeBlobSupport.REQUIRED)
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            largeBlob = LargeBlobExtensionOutput(supported = true)
        )

        val result = WebAuthnExtensionValidator.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationPassesIfLargeBlobNotRequired() {
        val inputs = AuthenticationExtensionsClientInputs(
            largeBlob = LargeBlobExtensionInput(support = LargeBlobExtensionInput.LargeBlobSupport.PREFERRED)
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            largeBlob = LargeBlobExtensionOutput(supported = false)
        )

        val result = WebAuthnExtensionValidator.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }
}
