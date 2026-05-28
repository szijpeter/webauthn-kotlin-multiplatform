package dev.webauthn.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Base64UrlBytesTest {
    @Test
    fun fromBytesMatchesRfc4648UrlSafeGoldenCases() {
        val cases = listOf(
            byteArrayOf() to "",
            "f".encodeToByteArray() to "Zg",
            "fo".encodeToByteArray() to "Zm8",
            "foo".encodeToByteArray() to "Zm9v",
            "foob".encodeToByteArray() to "Zm9vYg",
            "fooba".encodeToByteArray() to "Zm9vYmE",
            "foobar".encodeToByteArray() to "Zm9vYmFy",
            byteArrayOf(0xFB.toByte(), 0xEF.toByte(), 0xFF.toByte()) to "--__",
        )

        cases.forEach { (bytes, expectedEncoded) ->
            assertEquals(expectedEncoded, Base64UrlBytes.fromBytes(bytes).encoded())
        }
    }

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
    fun parseRejectsStandardBase64Alphabet() {
        val result = Base64UrlBytes.parse("++//")
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
