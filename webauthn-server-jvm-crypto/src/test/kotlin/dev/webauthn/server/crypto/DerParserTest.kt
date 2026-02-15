package dev.webauthn.server.crypto

import kotlin.test.Test
import kotlin.test.assertTrue
import java.util.Arrays

class DerParserTest {

    @Test
    fun testParseSimpleSequence() {
        // Sequence of two integers: 1, 2
        // Sequence tag: 0x30
        // Length: 6
        // Int tag: 0x02, Len: 1, Val: 1
        // Int tag: 0x02, Len: 1, Val: 2
        val der = byteArrayOf(
            0x30, 0x06,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x02
        )

        val parser = DerParser(der).readSequence()
        assertTrue(Arrays.equals(byteArrayOf(1), parser.readInteger()))
        assertTrue(Arrays.equals(byteArrayOf(2), parser.readInteger()))
    }

    @Test
    fun testParseOctetString() {
        // Octet String: "hi" (0x68, 0x69)
        // Tag: 0x04, Len: 2
        val der = byteArrayOf(0x04, 0x02, 0x68, 0x69)
        val parser = DerParser(der)
        val str = parser.readOctetString()
        assertTrue(Arrays.equals(byteArrayOf(0x68, 0x69), str))
    }

    @Test
    fun testParseLongLength() {
        // Octet String of 200 bytes
        // Tag: 0x04
        // Len: 0x81, 0xC8 (200)
        val content = ByteArray(200) { ((it % 255).toByte()) }
        val header = byteArrayOf(0x04, 0x81.toByte(), 0xC8.toByte())
        val der = header + content

        val parser = DerParser(der)
        val parsed = parser.readOctetString()
        assertTrue(Arrays.equals(content, parsed))
    }

    @Test
    fun testNestedParsing() {
        // Sequence containing an Octet String
        val content = byteArrayOf(0x04, 0x01, 0xFF.toByte())
        val der = byteArrayOf(0x30, 0x03) + content

        val seq = DerParser(der).readSequence()
        val octet = seq.readOctetString()
        assertTrue(Arrays.equals(byteArrayOf(0xFF.toByte()), octet))
    }
}
