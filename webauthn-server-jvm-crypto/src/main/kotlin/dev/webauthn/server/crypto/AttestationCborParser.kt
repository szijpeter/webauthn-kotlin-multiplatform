package dev.webauthn.server.crypto

/**
 * Shared CBOR parser for WebAuthn attestation objects.
 *
 * Extracts `fmt`, `authData`, and `attStmt` fields from the CBOR-encoded attestation object.
 * For `attStmt`, extracts packed-format fields: `alg`, `sig`, `x5c`, and `ecdaaKeyId`.
 */
internal data class ParsedAttestationObject(
    val fmt: String,
    val attStmtEntryCount: Int,
    val authDataBytes: ByteArray? = null,
    val alg: Long? = null,
    val sig: ByteArray? = null,
    val x5c: List<ByteArray>? = null,
    val ecdaaKeyId: ByteArray? = null,
    val ver: String? = null,
    val certInfo: ByteArray? = null,
    val response: ByteArray? = null,
)

internal fun parseAttestationObject(bytes: ByteArray): ParsedAttestationObject? {
    var offset = 0
    val mapHeader = readCborHeader(bytes, offset) ?: return null
    if (mapHeader.majorType != MAJOR_MAP || mapHeader.length == null) return null
    offset = mapHeader.nextOffset

    var fmt: String? = null
    var attStmtEntryCount: Int? = null
    var authDataBytes: ByteArray? = null
    var alg: Long? = null
    var sig: ByteArray? = null
    var x5c: List<ByteArray>? = null
    var ecdaaKeyId: ByteArray? = null
    var ver: String? = null
    var certInfo: ByteArray? = null
    var response: ByteArray? = null

    repeat(mapHeader.length.toInt()) {
        val key = readCborText(bytes, offset) ?: return null
        offset = key.second
        when (key.first) {
            "fmt" -> {
                val fmtVal = readCborText(bytes, offset) ?: return null
                fmt = fmtVal.first
                offset = fmtVal.second
            }
            "authData" -> {
                val bstr = readCborBytes(bytes, offset) ?: return null
                authDataBytes = bstr.first
                offset = bstr.second
            }
            "attStmt" -> {
                val stmtHeader = readCborHeader(bytes, offset) ?: return null
                if (stmtHeader.majorType != MAJOR_MAP || stmtHeader.length == null) return null
                attStmtEntryCount = stmtHeader.length.toInt()
                offset = stmtHeader.nextOffset
                repeat(attStmtEntryCount!!) {
                    val stmtKey = readCborText(bytes, offset) ?: return null
                    offset = stmtKey.second
                    when (stmtKey.first) {
                        "alg" -> {
                            val algVal = readCborInt(bytes, offset) ?: return null
                            alg = algVal.first
                            offset = algVal.second
                        }
                        "sig" -> {
                            val sigVal = readCborBytes(bytes, offset) ?: return null
                            sig = sigVal.first
                            offset = sigVal.second
                        }
                        "x5c" -> {
                            val arrayHeader = readCborHeader(bytes, offset) ?: return null
                            if (arrayHeader.majorType != MAJOR_ARRAY || arrayHeader.length == null) return null
                            offset = arrayHeader.nextOffset
                            val certs = mutableListOf<ByteArray>()
                            repeat(arrayHeader.length.toInt()) {
                                val cert = readCborBytes(bytes, offset) ?: return null
                                certs.add(cert.first)
                                offset = cert.second
                            }
                            x5c = certs
                        }
                        "ecdaaKeyId" -> {
                            val ecdaa = readCborBytes(bytes, offset) ?: return null
                            ecdaaKeyId = ecdaa.first
                            offset = ecdaa.second
                        }
                        "ver" -> {
                            val verVal = readCborText(bytes, offset) ?: return null
                            ver = verVal.first
                            offset = verVal.second
                        }
                        "certInfo" -> {
                            val infoVal = readCborBytes(bytes, offset) ?: return null
                            certInfo = infoVal.first
                            offset = infoVal.second
                        }
                        "response" -> {
                            val respVal = readCborBytes(bytes, offset) ?: return null
                            response = respVal.first
                            offset = respVal.second
                        }

                        else -> {
                            offset = skipCborItem(bytes, offset) ?: return null
                        }
                    }
                }
            }
            else -> {
                offset = skipCborItem(bytes, offset) ?: return null
            }
        }
    }

    return if (fmt != null && attStmtEntryCount != null) {
        ParsedAttestationObject(
            fmt = fmt!!,
            attStmtEntryCount = attStmtEntryCount!!,
            authDataBytes = authDataBytes,
            alg = alg,
            sig = sig,
            x5c = x5c,
            ecdaaKeyId = ecdaaKeyId,
            ver = ver,
            certInfo = certInfo,
            response = response,
        )
    } else {
        null
    }
}

// ---- Minimal CBOR helpers ----

internal data class CborHeader(
    val majorType: Int,
    val additionalInfo: Int,
    val length: Long?,
    val nextOffset: Int,
)

internal fun readCborHeader(bytes: ByteArray, offset: Int): CborHeader? {
    if (offset >= bytes.size) return null
    val initial = bytes[offset].toInt() and 0xFF
    val majorType = (initial ushr 5) and 0x07
    val additionalInfo = initial and 0x1F
    val lengthResult = readCborLength(bytes, offset + 1, additionalInfo) ?: return null
    return CborHeader(
        majorType = majorType,
        additionalInfo = additionalInfo,
        length = lengthResult.first,
        nextOffset = lengthResult.second,
    )
}

private fun readCborLength(bytes: ByteArray, offset: Int, additionalInfo: Int): Pair<Long?, Int>? {
    return when {
        additionalInfo in 0..23 -> additionalInfo.toLong() to offset
        additionalInfo == 24 -> if (offset + 1 <= bytes.size) {
            (bytes[offset].toInt() and 0xFF).toLong() to (offset + 1)
        } else null
        additionalInfo == 25 -> if (offset + 2 <= bytes.size) {
            bytes.readUint16(offset).toLong() to (offset + 2)
        } else null
        additionalInfo == 26 -> if (offset + 4 <= bytes.size) {
            bytes.readUint32(offset) to (offset + 4)
        } else null
        additionalInfo == 27 -> if (offset + 8 <= bytes.size) {
            bytes.readUint64(offset) to (offset + 8)
        } else null
        additionalInfo == 31 -> null to offset
        else -> null
    }
}

internal fun readCborText(bytes: ByteArray, offset: Int): Pair<String, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    if (header.majorType != MAJOR_TEXT || header.length == null) return null
    val length = header.length.toInt()
    if (length < 0 || header.nextOffset + length > bytes.size) return null
    val value = bytes.copyOfRange(header.nextOffset, header.nextOffset + length).decodeToString()
    return value to (header.nextOffset + length)
}

internal fun readCborBytes(bytes: ByteArray, offset: Int): Pair<ByteArray, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    if (header.majorType != MAJOR_BYTE_STRING || header.length == null) return null
    val length = header.length.toInt()
    if (length < 0 || header.nextOffset + length > bytes.size) return null
    val value = bytes.copyOfRange(header.nextOffset, header.nextOffset + length)
    return value to (header.nextOffset + length)
}

internal fun readCborInt(bytes: ByteArray, offset: Int): Pair<Long, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    return when (header.majorType) {
        MAJOR_UNSIGNED_INT -> {
            header.length?.let { it to header.nextOffset }
        }
        MAJOR_NEGATIVE_INT -> {
            header.length?.let { (-1L - it) to header.nextOffset }
        }
        else -> null
    }
}

internal fun skipCborItem(bytes: ByteArray, offset: Int): Int? {
    val header = readCborHeader(bytes, offset) ?: return null
    return when (header.majorType) {
        MAJOR_UNSIGNED_INT, MAJOR_NEGATIVE_INT -> header.nextOffset
        MAJOR_BYTE_STRING, MAJOR_TEXT -> {
            val length = header.length?.toInt() ?: return null
            val end = header.nextOffset + length
            if (end > bytes.size) return null
            end
        }
        MAJOR_ARRAY -> {
            val count = header.length?.toInt() ?: return null
            var next = header.nextOffset
            repeat(count) { next = skipCborItem(bytes, next) ?: return null }
            next
        }
        MAJOR_MAP -> {
            val count = header.length?.toInt() ?: return null
            var next = header.nextOffset
            repeat(count) {
                next = skipCborItem(bytes, next) ?: return null
                next = skipCborItem(bytes, next) ?: return null
            }
            next
        }
        MAJOR_TAG -> skipCborItem(bytes, header.nextOffset)
        MAJOR_SIMPLE_FLOAT -> header.nextOffset
        else -> null
    }
}


private fun ByteArray.readUint16(offset: Int): Int {
    return ((this[offset].toInt() and 0xFF) shl 8) or
        (this[offset + 1].toInt() and 0xFF)
}

private fun ByteArray.readUint32(offset: Int): Long {
    return ((this[offset].toLong() and 0xFF) shl 24) or
        ((this[offset + 1].toLong() and 0xFF) shl 16) or
        ((this[offset + 2].toLong() and 0xFF) shl 8) or
        (this[offset + 3].toLong() and 0xFF)
}

private fun ByteArray.readUint64(offset: Int): Long {
    return ((this[offset].toLong() and 0xFF) shl 56) or
        ((this[offset + 1].toLong() and 0xFF) shl 48) or
        ((this[offset + 2].toLong() and 0xFF) shl 40) or
        ((this[offset + 3].toLong() and 0xFF) shl 32) or
        ((this[offset + 4].toLong() and 0xFF) shl 24) or
        ((this[offset + 5].toLong() and 0xFF) shl 16) or
        ((this[offset + 6].toLong() and 0xFF) shl 8) or
        (this[offset + 7].toLong() and 0xFF)
}

internal const val MAJOR_UNSIGNED_INT: Int = 0
internal const val MAJOR_NEGATIVE_INT: Int = 1
internal const val MAJOR_BYTE_STRING: Int = 2
internal const val MAJOR_TEXT: Int = 3
internal const val MAJOR_ARRAY: Int = 4
internal const val MAJOR_MAP: Int = 5
internal const val MAJOR_TAG: Int = 6
internal const val MAJOR_SIMPLE_FLOAT: Int = 7
