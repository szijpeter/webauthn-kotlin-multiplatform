package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JvmCertificateSignatureVerifierTest {
    @Test
    fun verifiesEs256UsingDerCertificate() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val cert = TestCertificateFixtures.selfSignedEcCertificate(keyPair)
        val data = "es256-message".encodeToByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(data)
            sign()
        }

        assertTrue(
            SignumPrimitives.verifyWithCertificate(CoseAlgorithm.ES256, cert, data, signature),
            "Expected ES256 signature to verify with certificate public key",
        )
    }

    @Test
    fun verifiesRs256UsingDerCertificate() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cert = TestCertificateFixtures.selfSignedRsaCertificate(keyPair)
        val data = "rs256-message".encodeToByteArray()
        val signature = Signature.getInstance("SHA256withRSA").run {
            initSign(keyPair.private)
            update(data)
            sign()
        }

        assertTrue(
            SignumPrimitives.verifyWithCertificate(CoseAlgorithm.RS256, cert, data, signature),
            "Expected RS256 signature to verify with certificate public key",
        )
    }

    @Test
    fun failsForTamperedPayload() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cert = TestCertificateFixtures.selfSignedRsaCertificate(keyPair)
        val signature = Signature.getInstance("SHA256withRSA").run {
            initSign(keyPair.private)
            update("original".encodeToByteArray())
            sign()
        }

        assertFalse(
            SignumPrimitives.verifyWithCertificate(CoseAlgorithm.RS256, cert, "tampered".encodeToByteArray(), signature),
            "Expected tampered payload verification to fail",
        )
    }
}
