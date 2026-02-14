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
}
