package dev.webauthn.server.crypto

import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.cert.TrustAnchor
import java.security.cert.PKIXParameters
import java.security.cert.CertPathValidator
import java.security.cert.Certificate
import java.util.Collections

public class TrustChainVerifier(
    private val trustAnchorSource: TrustAnchorSource,
) {

    private val certFactory = CertificateFactory.getInstance("X.509")

    public fun verify(chain: List<X509Certificate>, aaguid: ByteArray? = null): ValidationResult<Unit> {
        if (chain.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Certificate chain is empty")),
            )
        }

        val anchorsBytes = trustAnchorSource.findTrustAnchors(aaguid)
        if (anchorsBytes.isEmpty()) {
             // If no trust anchors configured, we can't verify trust path.
             // For now, fail open? No, security critical.
             // But for scaffold/beta, maybe soft fail?
             // Specification says: "verify that attestationCert is issued by a trusted CA".
             // If we don't know any trusted CAs, we can't verify.
             return ValidationResult.Invalid(
                 listOf(WebAuthnValidationError.InvalidValue("x5c", "No trust anchors found for this authenticator")),
             )
        }

        val trustAnchors = anchorsBytes.mapNotNull { bytes ->
            try {
                val cert = certFactory.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
                TrustAnchor(cert, null)
            } catch (e: Exception) {
                // Log warning?
                null
            }
        }.toSet()

        if (trustAnchors.isEmpty()) {
             return ValidationResult.Invalid(
                 listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse trust anchors")),
             )
        }

        try {
            // Build CertPath
            // Note: input chain might include root or not.
            // CertPathValidator usually expects chain excluding trust anchor?
            // "The PKIX validation algorithm... expects the path to start with the target certificate and end with a certificate issued by the trust anchor."
            
            val certPath = certFactory.generateCertPath(chain)
            
            val params = PKIXParameters(trustAnchors)
            params.isRevocationEnabled = false // TODO: CRL/OCSP support
            
            val validator = CertPathValidator.getInstance("PKIX")
            validator.validate(certPath, params)
            
            return ValidationResult.Valid(Unit)
            
        } catch (e: java.security.cert.CertPathValidatorException) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Trust chain validation failed: ${e.message}")),
            )
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                 listOf(WebAuthnValidationError.InvalidValue("x5c", "Certificate validation error: ${e.message}")),
            )
        }
    }
}
