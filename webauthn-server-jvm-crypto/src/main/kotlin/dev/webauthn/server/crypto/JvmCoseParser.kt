package dev.webauthn.server.crypto

import dev.webauthn.crypto.CosePublicKeyMaterial

/**
 * Single dedicated component for COSE_Key parsing in the JVM crypto module.
 * Owns CBOR map parsing and map → [CosePublicKeyMaterial]. SPKI conversion is in [CoseToSpkiConverter].
 *
 * Support matrix (see COSE_SUPPORT.md):
 * - EC2 P-256 (kty=2, crv=1): supported
 * - RSA (kty=3): supported
 * - OKP / Ed25519 (kty=1): not supported; fails deterministically
 */
internal object JvmCoseParser {

    fun parseCoseKey(coseKey: ByteArray): CosePublicKeyMaterial? {
        val map = parseCoseMap(coseKey) ?: return null
        val kty = map[1L] as? Long ?: return null
        val alg = map[3L] as? Long

        // EC2 specific (labels -1, -2, -3)
        val crv = map[-1L] as? Long
        val x = map[-2L] as? ByteArray
        val y = map[-3L] as? ByteArray

        // RSA specific (labels -1 = n, -2 = e)
        val n = map[-1L] as? ByteArray
        val e = map[-2L] as? ByteArray

        return CosePublicKeyMaterial(
            kty = kty,
            alg = alg,
            crv = crv,
            x = x,
            y = y,
            n = n,
            e = e
        )
    }

    internal fun parseCoseMap(bytes: ByteArray): Map<Long, Any>? {
        var offset = 0
        val header = readCborHeader(bytes, offset) ?: return null
        if (header.majorType != MAJOR_MAP || header.length == null) return null
        offset = header.nextOffset

        val result = mutableMapOf<Long, Any>()
        repeat(header.length.toInt()) {
            val keyResult = readCborInt(bytes, offset) ?: return null
            val key = keyResult.first
            offset = keyResult.second

            val valueHeader = readCborHeader(bytes, offset) ?: return null
            when (valueHeader.majorType) {
                MAJOR_UNSIGNED_INT, MAJOR_NEGATIVE_INT -> {
                    val v = readCborInt(bytes, offset) ?: return null
                    result[key] = v.first
                    offset = v.second
                }
                MAJOR_BYTE_STRING -> {
                    val v = readCborBytes(bytes, offset) ?: return null
                    result[key] = v.first
                    offset = v.second
                }
                else -> {
                    offset = skipCborItem(bytes, offset) ?: return null
                }
            }
        }
        return result
    }
}
