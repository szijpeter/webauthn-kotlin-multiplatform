package dev.webauthn.server.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

class JvmDigestServiceTest {
    private val digest = JvmDigestService()

    @Test
    fun sha256ProducesKnownDigest() {
        val actual = digest.sha256("abc".encodeToByteArray())
        val expectedHex = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        assertEquals(expectedHex, actual.toHexString())
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }
}
