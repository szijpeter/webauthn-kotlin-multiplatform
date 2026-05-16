package dev.webauthn.server.crypto

import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class JvmCosePublicKeyDecoderTest {
    @Test
    fun decodesEc2AndNormalizes() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public as ECPublicKey
        val cose = TestCoseHelpers.coseBytesFromEcPublicKey(publicKey)
        val x = publicKey.w.affineX.toByteArray().ensureUnsignedFixedLength(32)
        val y = publicKey.w.affineY.toByteArray().ensureUnsignedFixedLength(32)

        val material = assertNotNull(SignumPrimitives.decodeCoseMaterial(cose))
        assertEquals(2L, material.kty)
        assertEquals(-7L, material.alg)
        assertEquals(1L, material.crv)
        assertContentEquals(x, material.x)
        assertContentEquals(y, material.y)

        val spki = assertNotNull(SignumPrimitives.toSubjectPublicKeyInfo(material))
        assertEquals(0x30, spki[0].toInt() and 0xFF)

        val uncompressed = assertNotNull(SignumPrimitives.toUncompressedEcPoint(material))
        assertEquals(65, uncompressed.size)
        assertEquals(0x04, uncompressed[0].toInt() and 0xFF)
    }

    @Test
    fun decodesRsaAndNormalizesSpki() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val cose = TestCoseHelpers.coseBytesFromRsaPublicKey(publicKey)
        val modulus = publicKey.modulus.toByteArray().ensureUnsignedFixedLength((publicKey.modulus.bitLength() + 7) / 8)
        val exponent = publicKey.publicExponent.toByteArray().ensureUnsignedFixedLength((publicKey.publicExponent.bitLength() + 7) / 8)

        val material = assertNotNull(SignumPrimitives.decodeCoseMaterial(cose))
        assertEquals(3L, material.kty)
        assertEquals(-257L, material.alg)
        assertContentEquals(modulus, material.n)
        assertContentEquals(exponent, material.e)

        val spki = assertNotNull(SignumPrimitives.toSubjectPublicKeyInfo(material))
        assertEquals(0x30, spki[0].toInt() and 0xFF)
    }

    private fun ByteArray.ensureUnsignedFixedLength(length: Int): ByteArray {
        if (size == length) return this
        if (size == length + 1 && first() == 0.toByte()) return copyOfRange(1, size)
        if (size < length) {
            val out = ByteArray(length)
            copyInto(out, destinationOffset = length - size)
            return out
        }
        return copyOfRange(size - length, size)
    }
}
