package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.LargeBlobExtensionInput
import dev.webauthn.model.LargeBlobExtensionOutput
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PrfExtensionOutput
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

    @Test
    fun registrationFailsIfPrfReportedDisabledButInputsProvided() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(bytes(1)),
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(enabled = false)
        )

        val result = WebAuthnExtensionValidator.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationFailsIfPrfRequestedButOutputMissing() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(bytes(1)),
            ),
        )

        val result = WebAuthnExtensionValidator.validateRegistrationExtensions(inputs, outputs = null)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFailsIfPrfRequestedButResultsMissing() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(bytes(1)),
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(
                enabled = true,
                results = null,
            ),
        )

        val result = WebAuthnExtensionValidator.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFailsIfPrfResultsMissingSecondOutput() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(bytes(1), bytes(2)),
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(
                results = AuthenticationExtensionsPRFValues(bytes(3)), // missing second
            ),
        )

        val result = WebAuthnExtensionValidator.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationPassesIfPrfResultsMatchRequestedOutputCount() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(bytes(1), bytes(2)),
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(
                results = AuthenticationExtensionsPRFValues(bytes(3), bytes(4)),
            ),
        )

        val result = WebAuthnExtensionValidator.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }

    private fun bytes(vararg value: Int): Base64UrlBytes =
        Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })
}
