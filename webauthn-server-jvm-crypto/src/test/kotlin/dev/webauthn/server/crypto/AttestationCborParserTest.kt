package dev.webauthn.server.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AttestationCborParserTest {

    // ---- readCborHeader ----

    @Test
    fun readCborHeaderReturnsNullForEmptyInput() {
        assertNull(readCborHeader(byteArrayOf(), 0))
    }

    @Test
    fun readCborHeaderReturnsNullForOffsetPastEnd() {
        assertNull(readCborHeader(byteArrayOf(0x00), 5))
    }

    @Test
    fun readCborHeaderParsesUnsignedIntZero() {
        val header = readCborHeader(byteArrayOf(0x00), 0)
        assertNotNull(header)
        assertEquals(MAJOR_UNSIGNED_INT, header.majorType)
        assertEquals(0L, header.length)
    }

    @Test
    fun readCborHeaderParsesUnsignedInt23() {
        val header = readCborHeader(byteArrayOf(0x17), 0)
        assertNotNull(header)
        assertEquals(MAJOR_UNSIGNED_INT, header.majorType)
        assertEquals(23L, header.length)
    }

    @Test
    fun readCborHeaderParsesOneByteLengthUnsignedInt() {
        // 24 = additional info 24, next byte is length
        val header = readCborHeader(byteArrayOf(0x18, 0x64), 0) // uint 100
        assertNotNull(header)
        assertEquals(MAJOR_UNSIGNED_INT, header.majorType)
        assertEquals(100L, header.length)
    }

    @Test
    fun readCborHeaderReturnNullForTruncatedOneByteLengthInt() {
        // additional info = 24 but no following byte
        assertNull(readCborHeader(byteArrayOf(0x18), 0))
    }

    @Test
    fun readCborHeaderParsesTwoByteLengthInt() {
        // 0x19 = uint with 2-byte length, 0x01 0x00 = 256
        val header = readCborHeader(byteArrayOf(0x19, 0x01, 0x00), 0)
        assertNotNull(header)
        assertEquals(MAJOR_UNSIGNED_INT, header.majorType)
        assertEquals(256L, header.length)
    }

    @Test
    fun readCborHeaderReturnsNullForTruncatedTwoByteLengthInt() {
        assertNull(readCborHeader(byteArrayOf(0x19, 0x01), 0))
    }

    @Test
    fun readCborHeaderParsesFourByteLengthInt() {
        // 0x1A = uint with 4-byte length, 0x00 0x01 0x00 0x00 = 65536
        val header = readCborHeader(byteArrayOf(0x1A, 0x00, 0x01, 0x00, 0x00), 0)
        assertNotNull(header)
        assertEquals(MAJOR_UNSIGNED_INT, header.majorType)
        assertEquals(65536L, header.length)
    }

    @Test
    fun readCborHeaderReturnsNullForTruncatedFourByteLengthInt() {
        assertNull(readCborHeader(byteArrayOf(0x1A, 0x00, 0x01), 0))
    }

    @Test
    fun readCborHeaderParsesNegativeIntHeader() {
        // 0x20 = negint(-1), value = -1 - 0 = -1
        val header = readCborHeader(byteArrayOf(0x20), 0)
        assertNotNull(header)
        assertEquals(MAJOR_NEGATIVE_INT, header.majorType)
        assertEquals(0L, header.length) // raw length before negation
    }

    @Test
    fun readCborHeaderParsesMapHeader() {
        // 0xA3 = map with 3 entries
        val header = readCborHeader(byteArrayOf(0xA3.toByte()), 0)
        assertNotNull(header)
        assertEquals(MAJOR_MAP, header.majorType)
        assertEquals(3L, header.length)
    }

    @Test
    fun readCborHeaderParsesIndefiniteLengthMapAsNullLength() {
        // 0xBF = map with indefinite length
        val header = readCborHeader(byteArrayOf(0xBF.toByte()), 0)
        assertNotNull(header)
        assertEquals(MAJOR_MAP, header.majorType)
        assertNull(header.length) // indefinite length
    }

    // ---- readCborText ----

    @Test
    fun readCborTextParsesAsciiString() {
        // 0x65 = text(5), "hello"
        val bytes = byteArrayOf(0x65) + "hello".encodeToByteArray()
        val result = readCborText(bytes, 0)
        assertNotNull(result)
        assertEquals("hello", result.first)
        assertEquals(bytes.size, result.second)
    }

    @Test
    fun readCborTextParsesEmptyString() {
        val result = readCborText(byteArrayOf(0x60), 0)
        assertNotNull(result)
        assertEquals("", result.first)
    }

    @Test
    fun readCborTextReturnsNullForByteString() {
        // 0x45 = bstr(5)
        val bytes = byteArrayOf(0x45, 0x01, 0x02, 0x03, 0x04, 0x05)
        assertNull(readCborText(bytes, 0))
    }

    @Test
    fun readCborTextReturnsNullForTruncatedPayload() {
        // text(5) but only 3 bytes follow
        val bytes = byteArrayOf(0x65, 0x41, 0x42, 0x43)
        assertNull(readCborText(bytes, 0))
    }

    // ---- readCborBytes ----

    @Test
    fun readCborBytesParsesValidBstr() {
        val payload = byteArrayOf(0x01, 0x02, 0x03)
        val bytes = byteArrayOf(0x43) + payload // bstr(3)
        val result = readCborBytes(bytes, 0)
        assertNotNull(result)
        assertTrue(payload.contentEquals(result.first))
    }

    @Test
    fun readCborBytesReturnsNullForTextString() {
        val bytes = byteArrayOf(0x63) + "abc".encodeToByteArray()
        assertNull(readCborBytes(bytes, 0))
    }

    @Test
    fun readCborBytesReturnsNullForTruncatedPayload() {
        // bstr(5) but only 2 bytes follow
        val bytes = byteArrayOf(0x45, 0x01, 0x02)
        assertNull(readCborBytes(bytes, 0))
    }

    // ---- readCborInt ----

    @Test
    fun readCborIntParsesPositiveIntegers() {
        val result = readCborInt(byteArrayOf(0x0A), 0) // uint 10
        assertNotNull(result)
        assertEquals(10L, result.first)
    }

    @Test
    fun readCborIntParsesNegativeIntegers() {
        val result = readCborInt(byteArrayOf(0x26), 0) // negint -7 (0x20 | 6 → -1-6 = -7)
        assertNotNull(result)
        assertEquals(-7L, result.first)
    }

    @Test
    fun readCborIntReturnsNullForTextString() {
        val bytes = byteArrayOf(0x63) + "abc".encodeToByteArray()
        assertNull(readCborInt(bytes, 0))
    }

    // ---- skipCborItem ----

    @Test
    fun skipCborItemSkipsUnsignedInt() {
        val result = skipCborItem(byteArrayOf(0x0A, 0xFF.toByte()), 0)
        assertEquals(1, result) // skipped 1 byte (uint 10)
    }

    @Test
    fun skipCborItemSkipsByteString() {
        val bytes = byteArrayOf(0x43, 0x01, 0x02, 0x03, 0xFF.toByte())
        val result = skipCborItem(bytes, 0)
        assertEquals(4, result) // header + 3 bytes
    }

    @Test
    fun skipCborItemSkipsNestedMap() {
        // map(1) { text(1)"a": uint(1) }
        val bytes = byteArrayOf(
            0xA1.toByte(), // map(1)
            0x61, 0x61, // text(1) "a"
            0x01, // uint(1)
            0xFF.toByte(), // trailing byte
        )
        val result = skipCborItem(bytes, 0)
        assertEquals(4, result) // skipped entire map
    }

    @Test
    fun skipCborItemSkipsArray() {
        // array(2) { uint(1), uint(2) }
        val bytes = byteArrayOf(
            0x82.toByte(), // array(2)
            0x01, 0x02, // uint(1), uint(2)
            0xFF.toByte(), // trailing
        )
        val result = skipCborItem(bytes, 0)
        assertEquals(3, result)
    }

    @Test
    fun skipCborItemReturnsNullForTruncatedByteString() {
        // bstr(5) but only 2 bytes follow
        assertNull(skipCborItem(byteArrayOf(0x45, 0x01, 0x02), 0))
    }

    @Test
    fun skipCborItemReturnsNullForEmptyInput() {
        assertNull(skipCborItem(byteArrayOf(), 0))
    }

    // ---- parseAttestationObject ----

    @Test
    fun parseAttestationObjectReturnsNullForEmptyInput() {
        assertNull(parseAttestationObject(byteArrayOf()))
    }

    @Test
    fun parseAttestationObjectReturnsNullForNonMapInput() {
        // 0x63 = text(3) "abc"
        assertNull(parseAttestationObject(byteArrayOf(0x63) + "abc".encodeToByteArray()))
    }

    @Test
    fun parseAttestationObjectReturnsNullForMissingFmt() {
        // map(1) { "attStmt": {} }
        val bytes = cborMap("attStmt" to cborMap())
        assertNull(parseAttestationObject(bytes))
    }

    @Test
    fun parseAttestationObjectReturnsNullForMissingAttStmt() {
        // map(1) { "fmt": "none" }
        val bytes = cborMap("fmt" to cborText("none"))
        assertNull(parseAttestationObject(bytes))
    }

    @Test
    fun parseAttestationObjectReturnsNullWhenAttStmtIsNotMap() {
        // map(2) { "fmt": "none", "attStmt": 42 }
        val bytes = cborMap("fmt" to cborText("none"), "attStmt" to cborUint(42))
        assertNull(parseAttestationObject(bytes))
    }

    @Test
    fun parseAttestationObjectParsesValidNoneFmt() {
        val bytes = cborMap(
            "fmt" to cborText("none"),
            "attStmt" to cborMap(),
        )
        val parsed = parseAttestationObject(bytes)
        assertNotNull(parsed)
        assertEquals("none", parsed.fmt)
        assertEquals(0, parsed.attStmtEntryCount)
        assertNull(parsed.authDataBytes)
        assertNull(parsed.alg)
        assertNull(parsed.sig)
        assertNull(parsed.x5c)
    }

    @Test
    fun parseAttestationObjectParsesPackedFieldsCorrectly() {
        val authData = byteArrayOf(0x01, 0x02, 0x03)
        val sigBytes = byteArrayOf(0x0A, 0x0B)
        val certBytes = byteArrayOf(0x30, 0x31)

        val bytes = cborMap(
            "fmt" to cborText("packed"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "alg" to cborNegInt(7), // -7 = ES256
                "sig" to cborBytes(sigBytes),
                "x5c" to cborArray(listOf(cborBytes(certBytes))),
            ),
        )
        val parsed = parseAttestationObject(bytes)
        assertNotNull(parsed)
        assertEquals("packed", parsed.fmt)
        assertEquals(3, parsed.attStmtEntryCount)
        assertTrue(authData.contentEquals(parsed.authDataBytes!!))
        assertEquals(-7L, parsed.alg)
        assertTrue(sigBytes.contentEquals(parsed.sig!!))
        assertNotNull(parsed.x5c)
        assertEquals(1, parsed.x5c!!.size)
        assertTrue(certBytes.contentEquals(parsed.x5c!![0]))
    }

    @Test
    fun parseAttestationObjectReturnsNullForIndefiniteLengthMap() {
        // indefinite-length map: 0xBF ... 0xFF
        val bytes = byteArrayOf(0xBF.toByte(), 0xFF.toByte())
        assertNull(parseAttestationObject(bytes))
    }

    @Test
    fun parseAttestationObjectReturnsNullForTruncatedInput() {
        // map(3) but only one entry follows
        val bytes = byteArrayOf(0xA3.toByte()) +
            cborText("fmt") + cborText("none")
        assertNull(parseAttestationObject(bytes))
    }

    // ---- CBOR builders for tests ----

    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        entries.forEach { (key, value) ->
            result = result + cborText(key) + value
        }
        return result
    }

    private fun cborArray(items: List<ByteArray>): ByteArray {
        var result = cborHeader(4, items.size)
        items.forEach { result = result + it }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val encoded = value.encodeToByteArray()
        return cborHeader(3, encoded.size) + encoded
    }

    private fun cborBytes(value: ByteArray): ByteArray {
        return cborHeader(2, value.size) + value
    }

    private fun cborUint(value: Int): ByteArray {
        return cborHeader(0, value)
    }

    private fun cborNegInt(posValue: Int): ByteArray {
        // Encode negative int: -1 - posValue is stored as major type 1 with raw value (posValue - 1)
        // For -7: stored as major type 1, additional info 6 → 0x26
        return cborHeader(1, posValue - 1)
    }

    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        val prefix = majorType shl 5
        return when {
            length < 24 -> byteArrayOf((prefix or length).toByte())
            length < 256 -> byteArrayOf((prefix or 24).toByte(), length.toByte())
            else -> byteArrayOf(
                (prefix or 25).toByte(),
                (length shr 8).toByte(),
                (length and 0xFF).toByte(),
            )
        }
    }
}
