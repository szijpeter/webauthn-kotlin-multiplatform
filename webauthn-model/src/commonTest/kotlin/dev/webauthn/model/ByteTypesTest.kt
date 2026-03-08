package dev.webauthn.model

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class ByteTypesTest {
    @Test
    fun immutableBytesUseContentBasedEqualityAndHashCode() {
        val first = ImmutableBytes.fromBytes(byteArrayOf(1, 2, 3, 4))
        val second = ImmutableBytes.fromBytes(byteArrayOf(1, 2, 3, 4))
        val third = ImmutableBytes.fromBytes(byteArrayOf(4, 3, 2, 1))

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertFalse(first == third)
    }

    @Test
    fun immutableBytesDoNotTrackSourceArrayMutation() {
        val source = byteArrayOf(7, 8, 9)
        val value = ImmutableBytes.fromBytes(source)

        source[0] = 42

        assertContentEquals(byteArrayOf(7, 8, 9), value.bytes())
    }

    @Test
    fun immutableBytesReturnDefensiveCopies() {
        val value = ImmutableBytes.fromBytes(byteArrayOf(5, 6, 7))
        val firstRead = value.bytes()

        firstRead[1] = 99

        assertContentEquals(byteArrayOf(5, 6, 7), value.bytes())
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
}
