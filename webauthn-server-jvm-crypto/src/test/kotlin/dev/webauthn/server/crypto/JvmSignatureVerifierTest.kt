package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JvmSignatureVerifierTest {

    private val verifier = JvmSignatureVerifier()

    // ---- ES256 ----

    @Test
    fun es256VerifiesValidSignature() {
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val data = "test data for ES256 verification".encodeToByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }

        val result = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = TestCoseHelpers.coseBytesFromPublicKey(kp.public),
            data = data,
            signature = sig,
        )
        assertTrue(result, "Valid ES256 signature should verify")
    }

    @Test
    fun es256FailsForTamperedData() {
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val data = "original data".encodeToByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }

        val tampered = "tampered data".encodeToByteArray()
        val result = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = TestCoseHelpers.coseBytesFromPublicKey(kp.public),
            data = tampered,
            signature = sig,
        )
        assertFalse(result, "ES256 should fail for tampered data")
    }

    @Test
    fun es256FailsForWrongKey() {
        val kp1 = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val kp2 = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val data = "signed by key1".encodeToByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp1.private)
            update(data)
            sign()
        }

        val result = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = TestCoseHelpers.coseBytesFromPublicKey(kp2.public), // wrong key
            data = data,
            signature = sig,
        )
        assertFalse(result, "ES256 should fail when verified with wrong key")
    }

    @Test
    fun es256VerifiesRawP1363Signature() {
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val data = "test data for ES256 raw signature verification".encodeToByteArray()
        val derSignature = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }
        val rawSignature = derEcdsaSignatureToP1363(derSignature)

        val result = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = TestCoseHelpers.coseBytesFromPublicKey(kp.public),
            data = data,
            signature = rawSignature,
        )
        assertTrue(result, "Valid ES256 raw (P1363) signature should verify")
    }

    @Test
    fun capturedAndroidAssertionVectorCanBeVerifiedWithJca() {
        val cosePublicKey = base64UrlDecode("pQECAyYgASFYIHflyS-aHVhwAzewMoOb5NS3wrABqgvYKVxzLYLXoRY6IlggJ5K-fCUDYnGk0SH-8wC05tBuSYdQUk45X4tBxNOSMgw")
        val rawAuthenticatorData = base64UrlDecode("1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWodAAAAAA")
        val clientDataJson = base64UrlDecode(
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSnBFMlhkeG1yTnFwZTFsb1lFY2ZtOEtfb1pmQWtFMVpTd0VJdU1FT0JPQSIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOlZiai1tUGU5eDBORWlIREdHM0VPaTA0RVRHVDVTSW9FYzNmMnpwYzdxQzgiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJkZXYud2ViYXV0aG4uc2FtcGxlcy5jb21wb3NlcGFzc2tleS5hbmRyb2lkIn0",
        )
        val signatureDer = base64UrlDecode("MEYCIQDK_YzkGEhtIf4K6XM8LAjU4f3qASY3J5cgggiQOW7Y6wIhAKqCT7k80zLi_GADyhg41TK6S32uaSJiZ_aGzM_gfiCk")
        val signedData = rawAuthenticatorData + MessageDigest.getInstance("SHA-256").digest(clientDataJson)

        val signumResult = verifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = cosePublicKey,
            data = signedData,
            signature = signatureDer,
        )

        val material = requireNotNull(SignumPrimitives.decodeCoseMaterial(cosePublicKey))
        val x = requireNotNull(material.x)
        val y = requireNotNull(material.y)
        assertEquals(1L, material.crv, "Captured COSE key should use P-256")

        val ecSpec = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
        val publicKey = KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(
                ECPoint(java.math.BigInteger(1, x), java.math.BigInteger(1, y)),
                ecSpec,
            ),
        )
        val jcaResult = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(signedData)
            verify(signatureDer)
        }

        assertTrue(jcaResult, "Captured assertion vector should verify with JCA baseline")
        assertEquals(
            jcaResult,
            signumResult,
            "Signum and JCA ES256 verification should agree for captured assertion vector",
        )
    }

    // ---- RS256 ----

    @Test
    fun rs256VerifiesValidSignature() {
        val kp = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        val data = "test data for RS256 verification".encodeToByteArray()
        val sig = Signature.getInstance("SHA256withRSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }

        val result = verifier.verify(
            algorithm = CoseAlgorithm.RS256,
            publicKeyCose = TestCoseHelpers.coseBytesFromPublicKey(kp.public),
            data = data,
            signature = sig,
        )
        assertTrue(result, "Valid RS256 signature should verify")
    }

    @Test
    fun rs256FailsForTamperedData() {
        val kp = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        val data = "original data".encodeToByteArray()
        val sig = Signature.getInstance("SHA256withRSA").run {
            initSign(kp.private)
            update(data)
            sign()
        }

        val tampered = "tampered data".encodeToByteArray()
        val result = verifier.verify(
            algorithm = CoseAlgorithm.RS256,
            publicKeyCose = TestCoseHelpers.coseBytesFromPublicKey(kp.public),
            data = tampered,
            signature = sig,
        )
        assertFalse(result, "RS256 should fail for tampered data")
    }

    private fun derEcdsaSignatureToP1363(der: ByteArray): ByteArray {
        require(der.size >= 8 && der[0] == 0x30.toByte()) { "Invalid DER ECDSA signature" }
        var offset = 2
        require(der[offset] == 0x02.toByte()) { "Invalid DER ECDSA signature: missing R" }
        offset++
        val rLength = der[offset].toInt() and 0xFF
        offset++
        val r = der.copyOfRange(offset, offset + rLength)
        offset += rLength
        require(der[offset] == 0x02.toByte()) { "Invalid DER ECDSA signature: missing S" }
        offset++
        val sLength = der[offset].toInt() and 0xFF
        offset++
        val s = der.copyOfRange(offset, offset + sLength)
        return toFixed32(r) + toFixed32(s)
    }

    private fun toFixed32(value: ByteArray): ByteArray {
        val normalized = if (value.size == 33 && value[0] == 0.toByte()) {
            value.copyOfRange(1, value.size)
        } else {
            value
        }
        require(normalized.size <= 32) { "ECDSA integer larger than 32 bytes" }
        return ByteArray(32 - normalized.size) + normalized
    }

    private fun base64UrlDecode(value: String): ByteArray {
        val padded = value.padEnd((value.length + 3) / 4 * 4, '=')
        return Base64.getUrlDecoder().decode(padded)
    }
}
