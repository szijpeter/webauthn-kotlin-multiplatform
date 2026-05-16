package dev.webauthn.cbor

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class CborByteScannerTest {
    @Test
    fun headerReturnsNullForNegativeOffset() {
        val result = readCborHeader(byteArrayOf(0x60), offset = -1)
        assertNull(result)
    }

    @Test
    fun lengthReturnsNullForNegativeOffset() {
        val result = readCborLength(
            bytes = byteArrayOf(0x18, 0x18),
            offset = -1,
            majorType = MAJOR_UNSIGNED_INT,
            additionalInfo = 24,
        )
        assertNull(result)
    }

    @Test
    fun unsignedReadersRejectOutOfBoundsOffsets() {
        assertFailsWith<IllegalArgumentException> {
            byteArrayOf(0x01).readUint16(0)
        }
        assertFailsWith<IllegalArgumentException> {
            byteArrayOf(0x01, 0x02, 0x03).readUint32(0)
        }
    }
}
