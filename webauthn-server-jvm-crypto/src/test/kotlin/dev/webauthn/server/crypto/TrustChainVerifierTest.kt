package dev.webauthn.server.crypto

import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertTrue

class TrustChainVerifierTest {

    private val validator = JvmCertificateChainValidator()

    @Test
    fun verifyReturnsValidWhenChainMatchesTrustAnchor() {
        val rootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootCert = TestCertificateFixtures.selfSignedRsaCertificate(rootKp, subjectCn = "Root CA")
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKp.public.encoded,
            issuerPrivateKey = rootKp.private,
        )

        val trustSource = TrustAnchorSource { _ -> listOf(rootCert) }
        val verifier = TrustChainVerifier(trustSource, validator)

        val result = verifier.verify(listOf(leafCert), null)
        assertTrue(result is ValidationResult.Valid, "Expected Valid, got $result")
    }

    @Test
    fun verifyReturnsInvalidForEmptyChain() {
        val rootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootCert = TestCertificateFixtures.selfSignedRsaCertificate(rootKp, subjectCn = "Root CA")

        val trustSource = TrustAnchorSource { _ -> listOf(rootCert) }
        val verifier = TrustChainVerifier(trustSource, validator)

        val result = verifier.verify(emptyList(), null)
        assertTrue(result is ValidationResult.Invalid, "Expected Invalid for empty chain, got $result")
    }

    @Test
    fun verifyReturnsInvalidWhenNoTrustAnchorsFound() {
        val rootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKp.public.encoded,
            issuerPrivateKey = rootKp.private,
        )

        // TrustAnchorSource returns empty list
        val trustSource = TrustAnchorSource { _ -> emptyList() }
        val verifier = TrustChainVerifier(trustSource, validator)

        val result = verifier.verify(listOf(leafCert), null)
        assertTrue(result is ValidationResult.Invalid, "Expected Invalid when no trust anchors found, got $result")
    }

    @Test
    fun verifyReturnsInvalidWhenChainDoesNotMatchAnchor() {
        val rootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val otherRootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKp.public.encoded,
            issuerPrivateKey = rootKp.private,
        )
        val wrongAnchor = TestCertificateFixtures.selfSignedRsaCertificate(otherRootKp, subjectCn = "Other Root")

        val trustSource = TrustAnchorSource { _ -> listOf(wrongAnchor) }
        val verifier = TrustChainVerifier(trustSource, validator)

        val result = verifier.verify(listOf(leafCert), null)
        assertTrue(result is ValidationResult.Invalid, "Expected Invalid for wrong trust anchor, got $result")
    }

    @Test
    fun verifyFallbackSignedByNextPassesForValidChain() {
        val rootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootCert = TestCertificateFixtures.selfSignedRsaCertificate(rootKp, subjectCn = "Root CA")
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKp.public.encoded,
            issuerPrivateKey = rootKp.private,
        )

        val trustSource = TrustAnchorSource { _ -> listOf(rootCert) }
        val verifier = TrustChainVerifier(trustSource, validator)

        val result = verifier.verifyFallbackSignedByNext(listOf(leafCert, rootCert))
        assertTrue(result is ValidationResult.Valid, "Expected Valid for signed-by-next fallback, got $result")
    }

    @Test
    fun verifyFallbackSignedByNextFailsForBrokenChain() {
        val rootKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val leafKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootCert = TestCertificateFixtures.selfSignedRsaCertificate(rootKp, subjectCn = "Root CA")
        val unrelatedRoot = TestCertificateFixtures.selfSignedRsaCertificate(
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair(),
            subjectCn = "Unrelated",
        )
        val leafCert = TestCertificateFixtures.issuedRsaCertificate(
            issuerCn = "Root CA",
            subjectCn = "Leaf",
            subjectPublicKeyInfo = leafKp.public.encoded,
            issuerPrivateKey = rootKp.private,
        )

        val trustSource = TrustAnchorSource { _ -> listOf(rootCert) }
        val verifier = TrustChainVerifier(trustSource, validator)

        val result = verifier.verifyFallbackSignedByNext(listOf(leafCert, unrelatedRoot))
        assertTrue(result is ValidationResult.Invalid, "Expected Invalid for broken chain, got $result")
    }
}
