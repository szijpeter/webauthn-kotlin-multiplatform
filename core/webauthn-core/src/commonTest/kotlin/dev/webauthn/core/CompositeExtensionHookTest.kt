package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.LargeBlobExtensionInput
import dev.webauthn.model.LargeBlobExtensionOutput
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalWebAuthnL3Api::class)
class CompositeExtensionHookTest {

    @Test
    fun emptyCompositeAlwaysPasses() {
        val composite = CompositeExtensionHook(emptyList())

        val regResult = composite.validateRegistrationExtensions(null, null)
        assertTrue(regResult is ValidationResult.Valid)

        val authResult = composite.validateAuthenticationExtensions(null, null)
        assertTrue(authResult is ValidationResult.Valid)
    }

    @Test
    fun singleHookErrorsAreForwarded() {
        val composite = CompositeExtensionHook(listOf(PrfExtensionHook))

        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1))),
        )
        val result = composite.validateRegistrationExtensions(inputs, outputs = null)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals(1, result.errors.size)
    }

    @Test
    fun errorsFromMultipleHooksAreAggregated() {
        val composite = CompositeExtensionHook(listOf(PrfExtensionHook, LargeBlobExtensionHook))

        // Both PRF and LargeBlob should fail
        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1))),
            largeBlob = LargeBlobExtensionInput(
                support = LargeBlobExtensionInput.LargeBlobSupport.REQUIRED,
            ),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = null,
            largeBlob = LargeBlobExtensionOutput(supported = false),
        )

        val result = composite.validateRegistrationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals(2, result.errors.size)

        val fields = result.errors.map { it.field }.toSet()
        assertTrue("extensions.prf" in fields)
        assertTrue("extensions.largeBlob" in fields)
    }

    @Test
    fun validResultsFromAllHooksProduceValid() {
        val composite = CompositeExtensionHook(listOf(PrfExtensionHook, LargeBlobExtensionHook))

        val result = composite.validateRegistrationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticationErrorsAreAlsoAggregated() {
        val composite = CompositeExtensionHook(listOf(PrfExtensionHook))

        val inputs = AuthenticationExtensionsClientInputs(
            prf = PrfExtensionInput(eval = AuthenticationExtensionsPRFValues(bytes(1), bytes(2))),
        )
        val outputs = AuthenticationExtensionsClientOutputs(
            prf = dev.webauthn.model.PrfExtensionOutput(
                results = AuthenticationExtensionsPRFValues(bytes(3)),
            ),
        )

        val result = composite.validateAuthenticationExtensions(inputs, outputs)
        assertTrue(result is ValidationResult.Invalid)
        assertEquals("extensions.prf.results.second", result.errors.single().field)
    }

    @Test
    fun invalidWithoutErrorsStaysInvalid() {
        val composite = CompositeExtensionHook(listOf(EmptyInvalidHook))

        val regResult = composite.validateRegistrationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(regResult is ValidationResult.Invalid)
        assertTrue(regResult.errors.isEmpty())

        val authResult = composite.validateAuthenticationExtensions(
            inputs = AuthenticationExtensionsClientInputs(),
            outputs = AuthenticationExtensionsClientOutputs(),
        )
        assertTrue(authResult is ValidationResult.Invalid)
        assertTrue(authResult.errors.isEmpty())
    }

    private object EmptyInvalidHook : WebAuthnExtensionHook {
        override fun validateRegistrationExtensions(
            inputs: AuthenticationExtensionsClientInputs?,
            outputs: AuthenticationExtensionsClientOutputs?,
        ): ValidationResult<Unit> = ValidationResult.Invalid(emptyList())

        override fun validateAuthenticationExtensions(
            inputs: AuthenticationExtensionsClientInputs?,
            outputs: AuthenticationExtensionsClientOutputs?,
        ): ValidationResult<Unit> = ValidationResult.Invalid(emptyList())
    }

    private fun bytes(vararg value: Int): Base64UrlBytes =
        Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })
}
