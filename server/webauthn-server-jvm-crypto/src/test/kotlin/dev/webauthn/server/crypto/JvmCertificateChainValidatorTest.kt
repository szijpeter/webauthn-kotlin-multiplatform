package dev.webauthn.server.crypto

import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JvmCertificateChainValidatorTest {
    private val validator = JvmCertificateChainValidator()

    @Test
    fun verifyPassesForLeafSignedByTrustedAnchor() {
        val rootKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootCert = TestCertificateFixtures.selfSignedRsaCertificate(rootKeyPair, subjectCn = "Root CA")
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKeyPair.public.encoded,
            issuerPrivateKey = rootKeyPair.private,
        )

        assertTrue(
            validator.verify(chainDer = listOf(leafCert), trustAnchorsDer = listOf(rootCert)),
            "Expected PKIX validation to pass with matching trust anchor",
        )
    }

    @Test
    fun verifyFailsForWrongTrustAnchor() {
        val rootKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val otherRootKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKeyPair.public.encoded,
            issuerPrivateKey = rootKeyPair.private,
        )
        val wrongAnchor = TestCertificateFixtures.selfSignedRsaCertificate(otherRootKeyPair, subjectCn = "Other Root")

        assertFalse(
            validator.verify(chainDer = listOf(leafCert), trustAnchorsDer = listOf(wrongAnchor)),
            "Expected PKIX validation to fail with non-matching trust anchor",
        )
    }

    @Test
    fun verifySignedByNextCoversFallbackScenario() {
        val rootKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootCert = TestCertificateFixtures.selfSignedRsaCertificate(rootKeyPair, subjectCn = "Root CA")
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKeyPair.public.encoded,
            issuerPrivateKey = rootKeyPair.private,
        )

        assertTrue(validator.verifySignedByNext(listOf(leafCert, rootCert)))

        val unrelatedRoot = TestCertificateFixtures.selfSignedRsaCertificate(
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair(),
            subjectCn = "Unrelated",
        )
        assertFalse(validator.verifySignedByNext(listOf(leafCert, unrelatedRoot)))
    }
}
