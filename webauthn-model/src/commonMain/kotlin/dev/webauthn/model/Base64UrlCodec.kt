package dev.webauthn.model

private const val INVALID = -1

private val decodeTable: IntArray = IntArray(256) { INVALID }.apply {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    chars.forEachIndexed { index, c ->
        this[c.code] = index
    }
}

private val encodeTable: CharArray = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray()

internal object Base64UrlCodec {
    fun decode(input: String): ByteArray? {
        if (input.isEmpty()) {
            return ByteArray(0)
        }

        // RFC 4648 base64/base64url cannot represent data with 1 trailing sextet.
        // For unpadded base64url, valid lengths are length % 4 in {0, 2, 3}.
        if (input.length % 4 == 1) {
            return null
        }

        if (input.any { it.code > 255 || decodeTable[it.code] == INVALID }) {
            return null
        }

        val outSize = (input.length * 6) / 8
        val out = ByteArray(outSize)

        var buffer = 0
        var bitsInBuffer = 0
        var outIndex = 0

        for (char in input) {
            buffer = (buffer shl 6) or decodeTable[char.code]
            bitsInBuffer += 6
            if (bitsInBuffer >= 8) {
                bitsInBuffer -= 8
                out[outIndex++] = ((buffer shr bitsInBuffer) and 0xFF).toByte()
            }
        }

        if (bitsInBuffer > 0) {
            val mask = (1 shl bitsInBuffer) - 1
            if ((buffer and mask) != 0) {
                return null
            }
        }

        return out
    }

    fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) {
            return ""
        }

        val result = StringBuilder((bytes.size * 4 + 2) / 3)
        var buffer = 0
        var bitsInBuffer = 0

        for (byte in bytes) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsInBuffer += 8
            while (bitsInBuffer >= 6) {
                bitsInBuffer -= 6
                result.append(encodeTable[(buffer shr bitsInBuffer) and 0x3F])
            }
        }

        if (bitsInBuffer > 0) {
            result.append(encodeTable[(buffer shl (6 - bitsInBuffer)) and 0x3F])
        }

        return result.toString()
    }
}
