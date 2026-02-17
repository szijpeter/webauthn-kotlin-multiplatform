package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CoseParseFailure
import dev.webauthn.crypto.CoseParseResult
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * P1-006: Deterministic COSE conformance vectors for malformed/unsupported inputs and strict rejection.
 * Decoder and SignatureVerifier must not fall back to raw bytes; unsupported key shapes fail deterministically.
 */
class CoseConformanceTest {

    private val decoder = JvmCosePublicKeyDecoder()
    private val normalizer = JvmCosePublicKeyNormalizer()
    private val parser = JvmCoseKeyParser()
    private val verifier = JvmSignatureVerifier()

    // ---- Malformed CBOR ----

    @Test
    fun malformedCbor_emptyInput_decodeReturnsNull() {
        assertNull(decoder.decode(byteArrayOf()))
    }

    @Test
    fun malformedCbor_truncatedMap_decodeReturnsNull() {
        // Map with length 2 but only one byte after header
        val truncated = byteArrayOf(0xA2.toByte()) // map of 2 pairs
        assertNull(decoder.decode(truncated))
    }

    @Test
    fun malformedCbor_wrongMajorType_decodeReturnsNull() {
        // Array (major 4) instead of map (major 5)
        val arrayHeader = byteArrayOf(0x83.toByte()) // array of 3
        assertNull(decoder.decode(arrayHeader))
    }

    @Test
    fun malformedCbor_truncatedByteString_decodeReturnsNull() {
        // Map with one entry: 1 (kty) -> bstr length 100 but no payload
        val badBstr = byteArrayOf(
            0xA1.toByte(), // map 1
            0x01, // key 1
            0x58, 0x64, // bstr length 100 (no 100 bytes following)
        )
        assertNull(decoder.decode(badBstr))
    }

    @Test
    fun malformedCbor_parsePublicKeyReturnsFailure() {
        val result = parser.parsePublicKey(byteArrayOf(0xFF.toByte()))
        assertTrue(result is CoseParseResult.Failure)
        assertTrue((result as CoseParseResult.Failure).reason is CoseParseFailure.MalformedCbor)
    }

    @Test
    fun unsupportedKeyType_okp_decodeSucceeds_normalizerReturnsNull() {
        // OKP (kty=1) Ed25519: crv=6, x
        val x = ByteArray(32) { it.toByte() }
        val cose = cborMap(
            1L to cborInt(1L),   // kty=OKP
            3L to cborInt(-8L),  // alg=EdDSA
            -1L to cborInt(6L),  // crv=Ed25519
            -2L to cborBytes(x),
        )
        val material = decoder.decode(cose)
        assertTrue(material != null && material.kty == 1L)
        assertNull(normalizer.toSubjectPublicKeyInfo(requireNotNull(material)))
    }

    // ---- Unsupported key shapes ----

    @Test
    fun unsupportedKeyType_parsePublicKeyReturnsUnsupportedKeyType() {
        val x = ByteArray(32) { it.toByte() }
        val cose = cborMap(
            1L to cborInt(1L),
            3L to cborInt(-8L),
            -1L to cborInt(6L),
            -2L to cborBytes(x),
        )
        val result = parser.parsePublicKey(cose)
        assertTrue(result is CoseParseResult.Failure)
        val reason = (result as CoseParseResult.Failure).reason
        assertTrue(reason is CoseParseFailure.UnsupportedKeyType && (reason as CoseParseFailure.UnsupportedKeyType).kty == 1L)
    }

    @Test
    fun unsupportedCurve_ec2CrvOtherThanP256_normalizerReturnsNull() {
        val x = ByteArray(32) { 1 }
        val y = ByteArray(32) { 2 }
        val cose = cborMap(
            1L to cborInt(2L),
            3L to cborInt(-7L),
            -1L to cborInt(2L), // crv=2 (P-384), not supported
            -2L to cborBytes(x),
            -3L to cborBytes(y),
        )
        val material = decoder.decode(cose)
        assertTrue(material != null)
        assertNull(normalizer.toSubjectPublicKeyInfo(requireNotNull(material)))
    }

    @Test
    fun unsupportedCurve_parsePublicKeyReturnsUnsupportedCurve() {
        val x = ByteArray(32) { 1 }
        val y = ByteArray(32) { 2 }
        val cose = cborMap(
            1L to cborInt(2L),
            3L to cborInt(-7L),
            -1L to cborInt(2L),
            -2L to cborBytes(x),
            -3L to cborBytes(y),
        )
        val result = parser.parsePublicKey(cose)
        assertTrue(result is CoseParseResult.Failure)
        val reason = (result as CoseParseResult.Failure).reason
        assertTrue(reason is CoseParseFailure.UnsupportedCurve && (reason as CoseParseFailure.UnsupportedCurve).crv == 2L)
    }

    @Test
    fun missingRequiredParameter_ec2MissingY_parsePublicKeyReturnsMissingRequiredParameter() {
        val x = ByteArray(32) { 1 }
        val cose = cborMap(
            1L to cborInt(2L),
            3L to cborInt(-7L),
            -1L to cborInt(1L),
            -2L to cborBytes(x),
            // -3 (y) missing
        )
        val result = parser.parsePublicKey(cose)
        assertTrue(result is CoseParseResult.Failure)
        val reason = (result as CoseParseResult.Failure).reason
        assertTrue(reason is CoseParseFailure.MissingRequiredParameter && (reason as CoseParseFailure.MissingRequiredParameter).label == "y")
    }

    // ---- Strict rejection: SignatureVerifier returns false ----

    @Test
    fun signatureVerifier_returnsFalseForMalformedCose() {
        val result = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = byteArrayOf(0x00, 0x01, 0x02), // not a COSE map
            data = byteArrayOf(1, 2, 3),
            signature = ByteArray(64),
        )
        assertFalse(result)
    }

    @Test
    fun signatureVerifier_returnsFalseForUnsupportedKeyShape() {
        val coseOkp = cborMap(
            1L to cborInt(1L),
            3L to cborInt(-8L),
            -1L to cborInt(6L),
            -2L to cborBytes(ByteArray(32)),
        )
        val result = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = coseOkp,
            data = byteArrayOf(1, 2, 3),
            signature = ByteArray(64),
        )
        assertFalse(result)
    }

    private fun cborMap(vararg entries: Pair<Long, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        entries.forEach { (k, v) -> result += cborInt(k) + v }
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
