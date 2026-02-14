package dev.webauthn.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Base64UrlBytesTest {
    @Test
    fun parseRejectsPadding() {
        val result = Base64UrlBytes.parse("YWJjZA==")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun parseAcceptsValidUrlSafeValue() {
        val result = Base64UrlBytes.parse("aGVsbG8")
        assertTrue(result is ValidationResult.Valid)
        assertEquals("aGVsbG8", result.value.encoded())
    }

    @Test
    fun parseRejectsInvalidAlphabetCharacter() {
        val result = Base64UrlBytes.parse("a+b")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun parseRejectsImpossibleUnpaddedLength() {
        val result = Base64UrlBytes.parse("A")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun parseRejectsWhitespace() {
        val result = Base64UrlBytes.parse("aG Vs bG8")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun roundTripEncodesAndDecodesForMultipleLengths() {
        for (size in 0..128) {
            val bytes = ByteArray(size) { index -> ((index * 37 + size) and 0xFF).toByte() }
            val encoded = Base64UrlBytes.fromBytes(bytes).encoded()
            val parsed = Base64UrlBytes.parse(encoded)
            assertTrue(parsed is ValidationResult.Valid)
            assertTrue(parsed.value.bytes().contentEquals(bytes))
        }
    }
}
