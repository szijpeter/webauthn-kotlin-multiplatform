package dev.webauthn.server.crypto

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * Test helpers to build COSE public key bytes from JCA keys.
 * Used so tests pass valid COSE to [SignatureVerifier] and attestation verifiers (no SPKI fallback).
 */
object TestCoseHelpers {

    private const val COSE_KTY_EC2 = 2L
    private const val COSE_KTY_RSA = 3L
    private const val COSE_CRV_P256 = 1L
    private const val COSE_ALG_ES256 = -7L
    private const val COSE_ALG_RS256 = -257L

    fun coseBytesFromEcPublicKey(publicKey: ECPublicKey): ByteArray {
        val w = publicKey.w
        val fieldSize = (publicKey.params.curve.field.fieldSize + 7) / 8
        val x = unsignedFixedLength(w.affineX.toByteArray(), fieldSize)
        val y = unsignedFixedLength(w.affineY.toByteArray(), fieldSize)
        return cborMap(
            cborInt(1L) to cborInt(COSE_KTY_EC2),
            cborInt(3L) to cborInt(COSE_ALG_ES256),
            cborInt(-1L) to cborInt(COSE_CRV_P256),
            cborInt(-2L) to cborBytes(x),
            cborInt(-3L) to cborBytes(y),
        )
    }

    fun coseBytesFromRsaPublicKey(publicKey: RSAPublicKey): ByteArray {
        val n = unsignedFixedLength(publicKey.modulus.toByteArray(), publicKey.modulus.bitLength().let { (it + 7) / 8 })
        val e = unsignedFixedLength(publicKey.publicExponent.toByteArray(), publicKey.publicExponent.bitLength().let { (it + 7) / 8 }.coerceAtLeast(1))
        return cborMap(
            cborInt(1L) to cborInt(COSE_KTY_RSA),
            cborInt(3L) to cborInt(COSE_ALG_RS256),
            cborInt(-1L) to cborBytes(n),
            cborInt(-2L) to cborBytes(e),
        )
    }

    fun coseBytesFromPublicKey(publicKey: java.security.PublicKey): ByteArray {
        return when (publicKey) {
            is ECPublicKey -> coseBytesFromEcPublicKey(publicKey)
            is RSAPublicKey -> coseBytesFromRsaPublicKey(publicKey)
            else -> error("Unsupported key type: ${publicKey::class.qualifiedName}")
        }
    }

    private fun unsignedFixedLength(bytes: ByteArray, length: Int): ByteArray {
        if (bytes.size == length) return bytes
        if (bytes.size == length + 1 && bytes[0].toInt() == 0) return bytes.copyOfRange(1, bytes.size)
        if (bytes.size < length) {
            val out = ByteArray(length)
            bytes.copyInto(out, length - bytes.size)
            return out
        }
        return bytes.copyOfRange(bytes.size - length, bytes.size)
    }

    private fun cborMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        entries.forEach { (k, v) -> result += k + v }
        return result
    }

    private fun cborInt(value: Long): ByteArray =
        if (value >= 0) cborHeaderLong(0, value) else cborHeaderLong(1, -1L - value)

    private fun cborBytes(bytes: ByteArray): ByteArray = cborHeader(2, bytes.size) + bytes

    private fun cborHeader(majorType: Int, length: Int): ByteArray = cborHeaderLong(majorType, length.toLong())

    private fun cborHeaderLong(majorType: Int, length: Long): ByteArray {
        val prefix = majorType shl 5
        return when {
            length < 24 -> byteArrayOf((prefix or length.toInt()).toByte())
            length < 256 -> byteArrayOf((prefix or 24).toByte(), length.toByte())
            length < 65536 -> byteArrayOf(
                (prefix or 25).toByte(),
                (length shr 8).toByte(),
                length.toByte(),
            )
            else -> byteArrayOf(
                (prefix or 26).toByte(),
                (length shr 24).toByte(),
                (length shr 16).toByte(),
                (length shr 8).toByte(),
                length.toByte(),
            )
        }
    }
}
