package dev.webauthn.server.crypto

/**
 * Minimal DER parser for ASN.1 structures.
 *
 * Supports sequential reading of DER-encoded data with focus on
 * minimal dependencies for parsing X.509 extensions.
 */
internal class DerParser(private val data: ByteArray) {
    private var pos = 0

    val isExhausted: Boolean
        get() = pos >= data.size

    data class Header(val tag: Int, val value: ByteArray)

    fun readNextTLV(): Header {
        return readHeader()
    }

    fun readSequence(): DerParser {
        val header = readHeader()
        if (header.tag != TAG_SEQUENCE) {
            throw IllegalArgumentException("Expected SEQUENCE (0x30), found 0x${header.tag.toString(16)}")
        }
        return DerParser(header.value)
    }

    fun readOctetString(): ByteArray {
        val header = readHeader()
        if (header.tag != TAG_OCTET_STRING) {
            throw IllegalArgumentException("Expected OCTET STRING (0x04), found 0x${header.tag.toString(16)}")
        }
        return header.value
    }

    fun readInteger(): ByteArray {
        val header = readHeader()
        if (header.tag != TAG_INTEGER && header.tag != TAG_ENUMERATED) {
            // Android Key Attestation sometimes uses ENUMERATED for SecurityLevel, treated same as INTEGER here
            throw IllegalArgumentException("Expected INTEGER (0x02) or ENUMERATED (0x0A), found 0x${header.tag.toString(16)}")
        }
        return header.value
    }

    fun skip(count: Int) {
        repeat(count) {
            readHeader()
        }
    }

    private fun readHeader(): Header {
        if (pos >= data.size) throw IllegalArgumentException("Unexpected end of DER data")

        var b = data[pos++].toInt() and 0xFF
        var tag = b
        
        // Handle high-tag-number form (multi-byte tags)
        if ((b and 0x1F) == 0x1F) {
            do {
                if (pos >= data.size) throw IllegalArgumentException("Unexpected end of DER data in tag")
                b = data[pos++].toInt() and 0xFF
                tag = (tag shl 8) or b
            } while ((b and 0x80) != 0)
        }

        val length = readLength()

        if (pos + length > data.size) {
            throw IllegalArgumentException("DER length $length exceeds available data")
        }

        val value = data.copyOfRange(pos, pos + length)
        pos += length

        return Header(tag, value)
    }

    private fun readLength(): Int {
        if (pos >= data.size) throw IllegalArgumentException("Unexpected end of DER data")

        val initial = data[pos++].toInt() and 0xFF
        if (initial < 0x80) {
            // definite, short form
            return initial
        }

        val byteCount = initial and 0x7F
        if (byteCount == 0 || byteCount > 4) {
             throw IllegalArgumentException("Unsupported DER length byte count: $byteCount")
        }

        if (pos + byteCount > data.size) {
            throw IllegalArgumentException("Unexpected end of DER data reading length")
        }

        var length = 0
        repeat(byteCount) {
            length = (length shl 8) or (data[pos++].toInt() and 0xFF)
        }

        if (length < 0) throw IllegalArgumentException("DER length negative (overflow)")

        return length
    }

    fun readSet(): DerParser {
        val header = readHeader()
        if (header.tag != TAG_SET) {
            throw IllegalArgumentException("Expected SET (0x31), found 0x${header.tag.toString(16)}")
        }
        return DerParser(header.value)
    }

    companion object {
        const val TAG_INTEGER = 0x02
        const val TAG_OCTET_STRING = 0x04
        const val TAG_ENUMERATED = 0x0A
        const val TAG_SEQUENCE = 0x30
        const val TAG_SET = 0x31
    }
}
