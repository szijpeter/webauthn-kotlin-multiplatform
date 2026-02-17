package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
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
}
