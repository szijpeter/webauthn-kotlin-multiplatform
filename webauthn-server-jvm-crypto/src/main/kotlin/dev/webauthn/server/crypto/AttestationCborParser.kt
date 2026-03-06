package dev.webauthn.server.crypto

import dev.webauthn.internal.cbor.MAJOR_ARRAY
import dev.webauthn.internal.cbor.MAJOR_MAP
import dev.webauthn.internal.cbor.readCborBytes
import dev.webauthn.internal.cbor.readCborHeader
import dev.webauthn.internal.cbor.readCborInt
import dev.webauthn.internal.cbor.readCborText
import dev.webauthn.internal.cbor.skipCborItem

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
    val mapLength = mapHeader.length ?: return null
    if (mapHeader.majorType != MAJOR_MAP) return null
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

    repeat(mapLength.toInt()) {
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
                val stmtLength = stmtHeader.length ?: return null
                if (stmtHeader.majorType != MAJOR_MAP) return null
                attStmtEntryCount = stmtLength.toInt()
                offset = stmtHeader.nextOffset
                repeat(attStmtEntryCount) {
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
                            val arrayLength = arrayHeader.length ?: return null
                            if (arrayHeader.majorType != MAJOR_ARRAY) return null
                            offset = arrayHeader.nextOffset
                            val certs = mutableListOf<ByteArray>()
                            repeat(arrayLength.toInt()) {
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
            fmt = fmt,
            attStmtEntryCount = attStmtEntryCount,
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
