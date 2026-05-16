package dev.webauthn.model

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class ByteTypesTest {
    @Test
    fun base64UrlBytesUseContentBasedEqualityAndHashCode() {
        val first = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3, 4))
        val second = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3, 4))
        val third = Base64UrlBytes.fromBytes(byteArrayOf(4, 3, 2, 1))

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertFalse(first == third)
    }

    @Test
    fun base64UrlBytesDoNotTrackSourceArrayMutation() {
        val source = byteArrayOf(7, 8, 9)
        val value = Base64UrlBytes.fromBytes(source)

        source[0] = 42

        assertContentEquals(byteArrayOf(7, 8, 9), value.bytes())
    }

    @Test
    fun base64UrlBytesReturnDefensiveCopies() {
        val value = Base64UrlBytes.fromBytes(byteArrayOf(5, 6, 7))
        val firstRead = value.bytes()

        firstRead[1] = 99

        assertContentEquals(byteArrayOf(5, 6, 7), value.bytes())
    }

    @Test
    fun byteWrappersRedactPayloadsInToString() {
        val base = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3, 4))
        val rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 7 })
        val aaguid = Aaguid.fromBytes(ByteArray(16) { 9 })

        assertEquals("Base64UrlBytes(4 bytes)", base.toString())
        assertEquals("RpIdHash(32 bytes)", rpIdHash.toString())
        assertEquals("Aaguid(16 bytes)", aaguid.toString())
    }

    @Test
    fun rpIdHashRequires32Bytes() {
        assertFailsWith<IllegalArgumentException> {
            RpIdHash.fromBytes(ByteArray(31))
        }
    }

    @Test
    fun aaguidRequires16Bytes() {
        assertFailsWith<IllegalArgumentException> {
            Aaguid.fromBytes(ByteArray(15))
        }
    }

    @Test
    fun clientDataHashRequires32Bytes() {
        assertFailsWith<IllegalArgumentException> {
            ClientDataHash.fromBytes(ByteArray(31))
        }
    }

    @Test
    fun cosePublicKeyExposesBytesAndEncodesSafely() {
        val value = CosePublicKey.fromBytes(byteArrayOf(0x01, 0x02, 0x03))

        assertContentEquals(byteArrayOf(0x01, 0x02, 0x03), value.bytes())
        assertEquals("CosePublicKey(3 bytes)", value.toString())
    }
}
