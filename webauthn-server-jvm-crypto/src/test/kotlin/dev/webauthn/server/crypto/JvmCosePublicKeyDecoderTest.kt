package dev.webauthn.server.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class JvmCosePublicKeyDecoderTest {
    private val decoder = JvmCosePublicKeyDecoder()
    private val normalizer = JvmCosePublicKeyNormalizer()

    @Test
    fun decodesEc2AndNormalizes() {
        val x = ByteArray(32) { (it + 1).toByte() }
        val y = ByteArray(32) { (it + 33).toByte() }
        val cose = cborMap(
            1L to cborInt(2L), // kty=EC2
            3L to cborInt(-7L), // alg=ES256
            -1L to cborInt(1L), // crv=P-256
            -2L to cborBytes(x),
            -3L to cborBytes(y),
        )

        val material = assertNotNull(decoder.decode(cose))
        assertEquals(2L, material.kty)
        assertEquals(-7L, material.alg)
        assertEquals(1L, material.crv)
        assertContentEquals(x, material.x)
        assertContentEquals(y, material.y)

        val spki = assertNotNull(normalizer.toSubjectPublicKeyInfo(material))
        assertEquals(0x30, spki[0].toInt() and 0xFF)

        val uncompressed = assertNotNull(normalizer.toUncompressedEcPoint(material))
        assertEquals(65, uncompressed.size)
        assertEquals(0x04, uncompressed[0].toInt() and 0xFF)
    }

    @Test
    fun decodesRsaAndNormalizesSpki() {
        val modulus = ByteArray(256) { (it + 1).toByte() }
        val exponent = byteArrayOf(0x01, 0x00, 0x01) // 65537
        val cose = cborMap(
            1L to cborInt(3L), // kty=RSA
            3L to cborInt(-257L), // alg=RS256
            -1L to cborBytes(modulus),
            -2L to cborBytes(exponent),
        )

        val material = assertNotNull(decoder.decode(cose))
        assertEquals(3L, material.kty)
        assertEquals(-257L, material.alg)
        assertContentEquals(modulus, material.n)
        assertContentEquals(exponent, material.e)

        val spki = assertNotNull(normalizer.toSubjectPublicKeyInfo(material))
        assertEquals(0x30, spki[0].toInt() and 0xFF)
    }

    private fun cborMap(vararg entries: Pair<Long, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        for ((key, value) in entries) {
            result += cborInt(key)
            result += value
        }
        return result
    }

    private fun cborBytes(bytes: ByteArray): ByteArray = cborHeader(2, bytes.size) + bytes

    private fun cborInt(value: Long): ByteArray {
        return if (value >= 0) cborHeaderLong(0, value) else cborHeaderLong(1, -1L - value)
    }

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
