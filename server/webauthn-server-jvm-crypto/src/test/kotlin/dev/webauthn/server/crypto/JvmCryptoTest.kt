package dev.webauthn.server.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

class JvmCryptoTest {
    @Test
    fun rpIdHashIsSha256Length() {
        val hash = JvmRpIdHasher().hashRpId("example.com")
        assertEquals(32, hash.size)
    }
}
