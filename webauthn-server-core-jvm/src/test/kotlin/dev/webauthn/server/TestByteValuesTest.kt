package dev.webauthn.server

import kotlin.test.Test
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
}
