package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalWebAuthnL3Api::class)
class PrfExtensionHookTest {

    @Test
    fun registrationPassesWhenNoPrfRequested() {
        val result = PrfExtensionHook.validateRegistrationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationPassesWhenNullInputs() {
        val result = PrfExtensionHook.validateRegistrationExtensions(
            inputs = null,
            outputs = null,
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationFailsWhenPrfRequestedButOutputMissing() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1))),
        )
        val result = PrfExtensionHook.validateRegistrationExtensions(inputs, outputs = null)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals("extensions.prf", result.errors.single().field)
    }

    @Test
    fun registrationFailsWhenPrfDisabledButEvalProvided() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1))),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(enabled = false),
        )
        val result = PrfExtensionHook.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals("extensions.prf.enabled", result.errors.single().field)
    }

    @Test
    fun registrationPassesWhenPrfRequestedAndOutputPresent() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1))),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(enabled = true),
        )
        val result = PrfExtensionHook.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticationPassesWhenNoPrfRequested() {
        val result = PrfExtensionHook.validateAuthenticationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticationFailsWhenPrfEvalRequestedButResultsMissing() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1))),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(enabled = true, results = null),
        )
        val result = PrfExtensionHook.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals("extensions.prf.results", result.errors.single().field)
    }

    @Test
    fun authenticationFailsWhenSecondOutputRequestedButMissing() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                eval = AuthenticationExtensionsPRFValues(bytes(1), bytes(2)),
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(
                results = AuthenticationExtensionsPRFValues(bytes(3)),
            ),
        )
        val result = PrfExtensionHook.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals("extensions.prf.results.second", result.errors.single().field)
    }

    @Test
    fun authenticationPassesWhenBothOutputsPresent() {
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
        val result = PrfExtensionHook.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticationFailsWhenEvalByCredentialRequestedButResultsMissing() {
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(
                evalByCredential = mapOf(
                    "cred-1" to AuthenticationExtensionsPRFValues(bytes(1)),
                ),
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(enabled = true, results = null),
        )
        val result = PrfExtensionHook.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
    }

    private fun bytes(vararg value: Int): Base64UrlBytes =
        Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })
}
