package dev.webauthn.client.ios

import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PrfExtensionInput
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class IosAuthorizationBridgePolicyTest {
    @Test
    fun includesSecurityKeyRequest_whenPrfNotRequested_andRuntimeSupportsSecurityKey() {
        assertTrue(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = false,
                iosMajorVersion = 15,
            ),
        )
    }

    @Test
    fun excludesSecurityKeyRequest_whenPrfIsRequested() {
        assertFalse(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = true,
                iosMajorVersion = 18,
            ),
        )
    }

    @Test
    fun excludesSecurityKeyRequest_whenRuntimeIsTooOld() {
        assertFalse(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = false,
                iosMajorVersion = 14,
            ),
        )
    }

    @Test
    fun shapesPrfInput_forSharedEval() {
        val sharedEval = prfValues(1, 2, 3)

        val shaped = shapePrfAssertionInput(
            PrfExtensionInput(eval = sharedEval),
        )

        assertNotNull(shaped)
        assertEquals("AQID", shaped.eval?.first?.encoded())
        assertNull(shaped.evalByCredential)
        assertTrue(isPrfRequested(shaped))
    }

    @Test
    fun shapesPrfInput_forPerCredentialEval() {
        val credentialId = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3))
        val perCredentialEval = prfValues(9, 8, 7)

        val shaped = shapePrfAssertionInput(
            PrfExtensionInput(
                evalByCredential = mapOf(
                    credentialId.encoded() to perCredentialEval,
                ),
            ),
        )

        assertNotNull(shaped)
        assertNull(shaped.eval)
        val mappedValues = shaped.evalByCredential
        assertNotNull(mappedValues)
        assertEquals(1, mappedValues.size)
        assertEquals(credentialId.encoded(), mappedValues.keys.single().encoded())
        assertEquals("CQgH", mappedValues.values.single().first.encoded())
    }

    @Test
    fun shapesPrfInput_forCombinedSharedAndPerCredentialEval() {
        val credentialId = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6))

        val shaped = shapePrfAssertionInput(
            PrfExtensionInput(
                eval = prfValues(1, 1, 1),
                evalByCredential = mapOf(
                    credentialId.encoded() to prfValues(2, 2, 2),
                ),
            ),
        )

        assertNotNull(shaped)
        assertNotNull(shaped.eval)
        val perCredential = shaped.evalByCredential
        assertNotNull(perCredential)
        assertEquals(1, perCredential.size)
    }

    @Test
    fun rejectsMalformedEvalByCredentialKey() {
        assertFailsWith<IllegalArgumentException> {
            shapePrfAssertionInput(
                PrfExtensionInput(
                    evalByCredential = mapOf(
                        "not-base64==" to prfValues(1, 2, 3),
                    ),
                ),
            )
        }
    }

    @Test
    fun doesNotTreatEmptyEvalByCredentialAsPrfRequest() {
        val shaped = shapePrfAssertionInput(
            PrfExtensionInput(
                evalByCredential = emptyMap(),
            ),
        )
        assertNull(shaped)
        assertFalse(isPrfRequested(shaped))
    }

    @Test
    fun excludesSecurityKeyRequest_whenPrfIsRequestedViaEvalByCredential() {
        val credentialId = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3))
        val shaped = shapePrfAssertionInput(
            PrfExtensionInput(
                evalByCredential = mapOf(
                    credentialId.encoded() to prfValues(3, 3, 3),
                ),
            ),
        )
        assertTrue(isPrfRequested(shaped))
        assertFalse(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = isPrfRequested(shaped),
                iosMajorVersion = 18,
            ),
        )
    }

    private fun prfValues(vararg bytes: Int): AuthenticationExtensionsPRFValues {
        return AuthenticationExtensionsPRFValues(
            first = Base64UrlBytes.fromBytes(ByteArray(bytes.size) { index -> bytes[index].toByte() }),
        )
    }
}
