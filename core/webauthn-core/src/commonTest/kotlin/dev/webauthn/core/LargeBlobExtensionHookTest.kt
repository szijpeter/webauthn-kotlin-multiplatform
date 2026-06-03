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
class LargeBlobExtensionHookTest {

    @Test
    fun registrationPassesWhenNoLargeBlobRequested() {
        val result = LargeBlobExtensionHook.validateRegistrationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationPassesWhenNullInputs() {
        val result = LargeBlobExtensionHook.validateRegistrationExtensions(
            inputs = null,
            outputs = null,
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationFailsWhenLargeBlobRequiredButNotSupported() {
        val inputs = AuthenticationExtensionsClientInputs(
            largeBlob = LargeBlobExtensionInput(
                support = LargeBlobExtensionInput.LargeBlobSupport.REQUIRED,
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            largeBlob = LargeBlobExtensionOutput(supported = false),
        )
        val result = LargeBlobExtensionHook.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationPassesWhenLargeBlobRequiredAndSupported() {
        val inputs = AuthenticationExtensionsClientInputs(
            largeBlob = LargeBlobExtensionInput(
                support = LargeBlobExtensionInput.LargeBlobSupport.REQUIRED,
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            largeBlob = LargeBlobExtensionOutput(supported = true),
        )
        val result = LargeBlobExtensionHook.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationPassesWhenLargeBlobPreferred() {
        val inputs = AuthenticationExtensionsClientInputs(
            largeBlob = LargeBlobExtensionInput(
                support = LargeBlobExtensionInput.LargeBlobSupport.PREFERRED,
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            largeBlob = LargeBlobExtensionOutput(supported = false),
        )
        val result = LargeBlobExtensionHook.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticationAlwaysPasses() {
        val result = LargeBlobExtensionHook.validateAuthenticationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(result is ValidationResult.Valid)
    }
}
