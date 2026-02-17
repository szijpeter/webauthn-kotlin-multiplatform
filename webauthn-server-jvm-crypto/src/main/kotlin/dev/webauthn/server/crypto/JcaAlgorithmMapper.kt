package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm

/**
 * Shared JCA algorithm mapping for attestation and signature verification.
 * Replaces repeated when(algorithm) / jcaParams blocks across JvmCertificateSignatureVerifier,
 * JcaSignatureVerifier, and SignumSignatureVerifier.
 */
public object JcaAlgorithmMapper {

    public fun signatureAlgorithm(cose: CoseAlgorithm): String =
        when (cose) {
            CoseAlgorithm.ES256 -> "SHA256withECDSA"
            CoseAlgorithm.RS256 -> "SHA256withRSA"
            CoseAlgorithm.EdDSA -> "Ed25519"
        }

    public fun keyFactoryAlgorithm(cose: CoseAlgorithm): String =
        when (cose) {
            CoseAlgorithm.ES256 -> "EC"
            CoseAlgorithm.RS256 -> "RSA"
            CoseAlgorithm.EdDSA -> "Ed25519"
        }
}
