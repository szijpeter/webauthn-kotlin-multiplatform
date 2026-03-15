package dev.webauthn.internal.cbor

/**
 * Internal CBOR byte scanner helpers shared across parser modules.
 *
 * This package is not part of the supported public API surface.
 */
public data class CborHeader(
    val majorType: Int,
    val additionalInfo: Int,
    val length: Long?,
    val nextOffset: Int,
)

@Suppress("MagicNumber")
public fun readCborHeader(bytes: ByteArray, offset: Int): CborHeader? {
    if (offset < 0) return null
    if (offset >= bytes.size) return null
    val initial = bytes[offset].toInt() and 0xFF
    val majorType = (initial ushr 5) and 0x07
    val additionalInfo = initial and 0x1F
    val lengthResult = readCborLength(bytes, offset + 1, majorType, additionalInfo) ?: return null
    return CborHeader(
        majorType = majorType,
        additionalInfo = additionalInfo,
        length = lengthResult.first,
        nextOffset = lengthResult.second,
    )
}

@Suppress("CyclomaticComplexMethod", "MagicNumber")
public fun readCborLength(bytes: ByteArray, offset: Int, majorType: Int, additionalInfo: Int): Pair<Long?, Int>? {
    if (offset < 0) return null
    return when {
        additionalInfo < 24 -> additionalInfo.toLong() to offset
        additionalInfo == 24 -> {
            if (!hasRemainingBytes(bytes.size, offset, 1)) return null
            val value = (bytes[offset].toInt() and 0xFF).toLong()
            if (majorType != MAJOR_SIMPLE_FLOAT && value < 24) return null
            value to (offset + 1)
        }

        additionalInfo == 25 -> {
            if (!hasRemainingBytes(bytes.size, offset, 2)) return null
            val value = bytes.readUint16(offset).toLong()
            if (majorType != MAJOR_SIMPLE_FLOAT && value < 256) return null
            value to (offset + 2)
        }

        additionalInfo == 26 -> {
            if (!hasRemainingBytes(bytes.size, offset, 4)) return null
            val value = bytes.readUint32(offset)
            if (majorType != MAJOR_SIMPLE_FLOAT && value < 65536) return null
            value to (offset + 4)
        }

        additionalInfo == 27 -> {
            if (!hasRemainingBytes(bytes.size, offset, 8)) return null
            val value = bytes.readUint64(offset)
            if (majorType != MAJOR_SIMPLE_FLOAT) {
                if (value < 0) return null
                if (value < 4294967296L) return null
            }
            value to (offset + 8)
        }

        additionalInfo == 31 -> null to offset
        else -> null
    }
}

@Suppress("MagicNumber")
public fun readCborText(bytes: ByteArray, offset: Int): Pair<String, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    if (header.majorType != MAJOR_TEXT || header.length == null) return null
    val length = header.length.toValidCborLengthInt() ?: return null
    if (!hasRemainingBytes(bytes.size, header.nextOffset, length)) return null
    val value = runCatching {
        bytes.decodeToString(
            startIndex = header.nextOffset,
            endIndex = header.nextOffset + length,
            throwOnInvalidSequence = true,
        )
    }.getOrNull() ?: return null
    return value to (header.nextOffset + length)
}

@Suppress("MagicNumber")
public fun readCborBytes(bytes: ByteArray, offset: Int): Pair<ByteArray, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    if (header.majorType != MAJOR_BYTE_STRING || header.length == null) return null
    val length = header.length.toValidCborLengthInt() ?: return null
    if (!hasRemainingBytes(bytes.size, header.nextOffset, length)) return null
    val value = bytes.copyOfRange(header.nextOffset, header.nextOffset + length)
    return value to (header.nextOffset + length)
}

public fun readCborInt(bytes: ByteArray, offset: Int): Pair<Long, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    return when (header.majorType) {
        MAJOR_UNSIGNED_INT -> header.length?.let { it to header.nextOffset }
        MAJOR_NEGATIVE_INT -> header.length?.let { (-1L - it) to header.nextOffset }
        else -> null
    }
}

@Suppress("CyclomaticComplexMethod", "MagicNumber")
public fun skipCborItem(bytes: ByteArray, offset: Int, depth: Int = 0): Int? {
    if (depth > MAX_CBOR_RECURSION) return null
    val header = readCborHeader(bytes, offset) ?: return null
    return when (header.majorType) {
        MAJOR_UNSIGNED_INT, MAJOR_NEGATIVE_INT -> header.nextOffset
        MAJOR_BYTE_STRING, MAJOR_TEXT -> {
            val length = header.length.toValidCborLengthInt() ?: return null
            if (!hasRemainingBytes(bytes.size, header.nextOffset, length)) return null
            val end = header.nextOffset + length
            return end
        }

        MAJOR_ARRAY -> {
            val count = header.length.toValidCborLengthInt() ?: return null
            var next = header.nextOffset
            repeat(count) { next = skipCborItem(bytes, next, depth + 1) ?: return null }
            next
        }

        MAJOR_MAP -> {
            val count = header.length.toValidCborLengthInt() ?: return null
            var next = header.nextOffset
            repeat(count) {
                next = skipCborItem(bytes, next, depth + 1) ?: return null
                next = skipCborItem(bytes, next, depth + 1) ?: return null
            }
            next
        }

        MAJOR_TAG -> skipCborItem(bytes, header.nextOffset, depth + 1)
        MAJOR_SIMPLE_FLOAT -> if (header.additionalInfo in 0..27) header.nextOffset else null
        else -> null
    }
}

@Suppress("MagicNumber")
public fun ByteArray.readUint16(offset: Int): Int {
    require(hasRemainingBytes(size, offset, 2)) { "Need 2 bytes from offset $offset, size=$size" }
    return ((this[offset].toInt() and 0xFF) shl 8) or
        (this[offset + 1].toInt() and 0xFF)
}

@Suppress("MagicNumber")
public fun ByteArray.readUint32(offset: Int): Long {
    require(hasRemainingBytes(size, offset, 4)) { "Need 4 bytes from offset $offset, size=$size" }
    return ((this[offset].toLong() and 0xFF) shl 24) or
        ((this[offset + 1].toLong() and 0xFF) shl 16) or
        ((this[offset + 2].toLong() and 0xFF) shl 8) or
        (this[offset + 3].toLong() and 0xFF)
}

@Suppress("MagicNumber")
internal fun ByteArray.readUint64(offset: Int): Long {
    require(hasRemainingBytes(size, offset, 8)) { "Need 8 bytes from offset $offset, size=$size" }
    return ((this[offset].toLong() and 0xFF) shl 56) or
        ((this[offset + 1].toLong() and 0xFF) shl 48) or
        ((this[offset + 2].toLong() and 0xFF) shl 40) or
        ((this[offset + 3].toLong() and 0xFF) shl 32) or
        ((this[offset + 4].toLong() and 0xFF) shl 24) or
        ((this[offset + 5].toLong() and 0xFF) shl 16) or
        ((this[offset + 6].toLong() and 0xFF) shl 8) or
        (this[offset + 7].toLong() and 0xFF)
}

public const val MAJOR_UNSIGNED_INT: Int = 0
public const val MAJOR_NEGATIVE_INT: Int = 1
internal const val MAJOR_BYTE_STRING: Int = 2
internal const val MAJOR_TEXT: Int = 3
public const val MAJOR_ARRAY: Int = 4
public const val MAJOR_MAP: Int = 5
public const val MAJOR_TAG: Int = 6
public const val MAJOR_SIMPLE_FLOAT: Int = 7

private const val MAX_CBOR_RECURSION: Int = 32

private fun Long?.toValidCborLengthInt(): Int? {
    val length = this ?: return null
    if (length < 0 || length > Int.MAX_VALUE.toLong()) {
        return null
    }
    return length.toInt()
}

private fun hasRemainingBytes(totalSize: Int, offset: Int, length: Int): Boolean {
    if (offset < 0 || length < 0) return false
    return offset <= totalSize - length
}
