package dev.webauthn.cbor

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class CborGoldenScannerTest {
    @Test
    fun readsRepresentativeWebAuthnCborPrimitives() {
        val unsigned = readCborInt(byteArrayOf(0x0A), 0)
        val negative = readCborInt(byteArrayOf(0x24), 0)
        val text = readCborText(cborText("packed"), 0)
        val bytes = readCborBytes(cborBytes(byteArrayOf(0x01, 0x02, 0x03)), 0)

        assertEquals(10L to 1, unsigned)
        assertEquals(-5L to 1, negative)
        assertEquals("packed", text?.first)
        assertContentEquals(byteArrayOf(0x01, 0x02, 0x03), bytes?.first)
    }

    @Test
    fun skipTraversesAuthenticatorStyleNestedStructures() {
        val coseKey = cborMap(
            cborInt(1L) to cborInt(2L),
            cborInt(3L) to cborInt(-7L),
            cborInt(-1L) to cborInt(1L),
            cborInt(-2L) to cborBytes(ByteArray(32) { 0x11 }),
            cborInt(-3L) to cborBytes(ByteArray(32) { 0x22 }),
        )
        val extensionMap = cborMap(
            cborText("credProps") to cborMap(cborText("rk") to byteArrayOf(0xF5.toByte())),
        )
        val wrapper = cborArray(coseKey, extensionMap)

        assertEquals(wrapper.size, skipCborItem(wrapper, 0))
    }

    @Test
    fun rejectsIndefiniteLengthAndNonMinimalEncodings() {
        val indefiniteMap = byteArrayOf(0xBF.toByte(), 0xFF.toByte())
        val nonMinimalUint = byteArrayOf(0x18, 0x17)
        val nonMinimalByteString = byteArrayOf(0x58, 0x17) + ByteArray(23) { 0x01 }

        assertNull(skipCborItem(indefiniteMap, 0))
        assertNull(readCborInt(nonMinimalUint, 0))
        assertNull(readCborBytes(nonMinimalByteString, 0))
    }

    @Test
    fun rejectsTrailingTruncatedNestedItems() {
        val truncatedMap = byteArrayOf(
            0xA1.toByte(),
            0x63, 'f'.code.toByte(), 'm'.code.toByte(), 't'.code.toByte(),
        )

        assertNull(skipCborItem(truncatedMap, 0))
    }

    private fun cborArray(vararg items: ByteArray): ByteArray {
        var result = cborHeader(4, items.size)
        items.forEach { item -> result += item }
        return result
    }

    private fun cborMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        entries.forEach { (key, value) -> result += key + value }
        return result
    }

    private fun cborInt(value: Long): ByteArray =
        if (value >= 0) cborHeaderLong(0, value) else cborHeaderLong(1, -1L - value)

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return cborHeader(3, bytes.size) + bytes
    }

    private fun cborBytes(value: ByteArray): ByteArray = cborHeader(2, value.size) + value

    private fun cborHeader(majorType: Int, length: Int): ByteArray = cborHeaderLong(majorType, length.toLong())

    private fun cborHeaderLong(majorType: Int, length: Long): ByteArray {
        val prefix = majorType shl 5
        return when {
            length < 24 -> byteArrayOf((prefix or length.toInt()).toByte())
            length < 256 -> byteArrayOf((prefix or 24).toByte(), length.toByte())
            else -> error("Test helper only supports short lengths")
        }
    }
}
