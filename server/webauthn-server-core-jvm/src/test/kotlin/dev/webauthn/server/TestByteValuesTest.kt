package dev.webauthn.server

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class TestByteValuesTest {
    @Test
    fun base64UrlBytesRejectsOutOfRangeValues() {
        assertFailsWith<IllegalArgumentException> {
            base64UrlBytes(0x100)
        }
        assertFailsWith<IllegalArgumentException> {
            base64UrlBytes(-1)
        }
    }

    @Test
    fun base64UrlBytesAcceptsBoundaryValues() {
        assertContentEquals(byteArrayOf(0x00), base64UrlBytes(0).bytes())
        assertContentEquals(byteArrayOf(0xFF.toByte()), base64UrlBytes(255).bytes())
        assertContentEquals(byteArrayOf(0x00, 0xFF.toByte()), base64UrlBytes(0x00, 0xFF).bytes())
    }
}
