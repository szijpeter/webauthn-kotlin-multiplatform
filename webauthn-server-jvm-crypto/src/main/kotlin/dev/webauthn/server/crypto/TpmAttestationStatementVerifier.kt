package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Arrays

internal class TpmAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
) : AttestationVerifier {

    companion object {
        private const val TPM_GENERATED_VALUE = 0xFF544347.toInt()
        private const val TPM_ST_ATTEST_CERTIFY = 0x8017.toShort()
        private const val VERSION_2_0 = "2.0"
        private const val OID_TCG_KP_AIK_CERTIFICATE = "2.23.133.8.3"
    }

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationObject = parseAttestationObject(input.response.attestationObject.bytes())
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("attestationObject", "Malformed CBOR")),
            )

        // ... fmt, ver, fields checks ...

        if (attestationObject.fmt != "tpm") {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("fmt", "Format must be tpm")),
            )
        }

        // 1. Verify "ver" is "2.0"
        if (attestationObject.ver != VERSION_2_0) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("ver", "TPM version must be 2.0")),
            )
        }

        if (attestationObject.certInfo == null || attestationObject.sig == null || attestationObject.x5c.isNullOrEmpty()) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "certInfo, sig, and x5c are required")),
            )
        }
        
        if (attestationObject.ecdaaKeyId != null) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("ecdaaKeyId", "ECDAA not supported")),
            )
        }

        // 4. Verify signature over certInfo using x5c[0]
        val x5c = attestationObject.x5c
        val certFactory = CertificateFactory.getInstance("X.509")
        val leafCert: X509Certificate
        val certs: List<X509Certificate>
        try {
            certs = x5c.map { certFactory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
            leafCert = certs[0]
        } catch (e: Exception) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse certificate: ${e.message}")),
            )
        }
        
        if (trustAnchorSource != null) {
            val chainVerifier = TrustChainVerifier(trustAnchorSource)
            val aaguid = input.response.attestedCredentialData.aaguid
            val chainResult = chainVerifier.verify(certs, aaguid)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        }


        val algId = attestationObject.alg
        if (algId == null) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("alg", "Algorithm identifier missing")),
            )
        }
        val coseAlg = CoseAlgorithm.entries.find { it.code == algId.toInt() }
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("alg", "Unsupported algorithm: $algId")),
            )

        try {
            val signature = java.security.Signature.getInstance(jcaParams(coseAlg))
            signature.initVerify(leafCert.publicKey)
            signature.update(attestationObject.certInfo)
            if (!signature.verify(attestationObject.sig)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("sig", "Invalid signature over certInfo")),
                )
            }
        } catch (e: Exception) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("sig", "Signature verification error: ${e.message}")),
            )
        }

        // 5. Parse and verify certInfo
        try {
            val buffer = ByteBuffer.wrap(attestationObject.certInfo)
            
            // Magic (4 bytes)
            if (buffer.remaining() < 4) throw IllegalArgumentException("certInfo too short")
            val magic = buffer.int
            if (magic != TPM_GENERATED_VALUE) {
                 return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("certInfo", "Invalid magic: ${Integer.toHexString(magic)}")),
                )
            }

            // Type (2 bytes)
            if (buffer.remaining() < 2) throw IllegalArgumentException("certInfo too short")
            val type = buffer.short
            if (type != TPM_ST_ATTEST_CERTIFY) {
                 return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("certInfo", "Invalid type: ${Integer.toHexString(type.toInt() and 0xFFFF)}")),
                )
            }

            // qualifiedSigner (TPM2B_NAME) -> 2 bytes size + size bytes data
            if (buffer.remaining() < 2) throw IllegalArgumentException("certInfo too short")
            val qsLen = buffer.short.toInt() and 0xFFFF
            if (buffer.remaining() < qsLen) throw IllegalArgumentException("certInfo too short for qualifiedSigner")
            buffer.position(buffer.position() + qsLen) // Skip qualifiedSigner

            // extraData (TPM2B_DATA) -> 2 bytes size + size bytes data
            if (buffer.remaining() < 2) throw IllegalArgumentException("certInfo too short")
            val edLen = buffer.short.toInt() and 0xFFFF
            if (buffer.remaining() < edLen) throw IllegalArgumentException("certInfo too short for extraData")
            val extraData = ByteArray(edLen)
            buffer.get(extraData)

            // Verify extraData matches SHA-256(authData || clientDataHash)
            val clientDataHash = java.security.MessageDigest.getInstance("SHA-256").digest(input.response.clientDataJson.bytes())
            val expectedHash = java.security.MessageDigest.getInstance("SHA-256").digest(attestationObject.authDataBytes!! + clientDataHash)

            if (!Arrays.equals(extraData, expectedHash)) {
                 return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("certInfo", "extraData mismatch")),
                )
            }

            // Remaining fields (clockInfo, firmwareVersion, attested) ignored for now per logic requirements.
            
        } catch (e: Exception) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("certInfo", "Failed to parse certInfo: ${e.message}")),
            )
        }

        // 6. Verify AIK certificate constraints (extendedKeyUsage, etc)
        val aikResult = validateAikCert(leafCert)
        if (aikResult is ValidationResult.Invalid) {
            return aikResult
        }
        
        return ValidationResult.Valid(Unit)
    }

    private fun validateAikCert(cert: X509Certificate): ValidationResult<Unit> {
        // Version MUST be 3 (integer 2)
        if (cert.version != 3) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate version must be 3")),
            )
        }

        // Subject DN MUST NOT be empty
        if (cert.subjectX500Principal.name.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate subject must not be empty")),
            )
        }

        // Basic Constraints MUST have CA component set to false
        if (cert.basicConstraints != -1) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate must not be a CA")),
            )
        }

        // Extended Key Usage MUST contain "tcg-kp-AIKCertificate" (2.23.133.8.3)
        try {
            val eku = cert.extendedKeyUsage
            if (eku == null || !eku.contains(OID_TCG_KP_AIK_CERTIFICATE)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate missing tcg-kp-AIKCertificate EKU")),
                )
            }
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse EKU: ${e.message}")),
            )
        }

        // If SAN is present, it MUST NOT be critical
        val criticalOids = cert.criticalExtensionOIDs
        if (criticalOids != null && criticalOids.contains("2.5.29.17")) { // OID for SubjectAlternativeName
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate SAN extension must not be critical")),
            )
        }

        return ValidationResult.Valid(Unit)
    }

    private fun jcaParams(alg: CoseAlgorithm): String {
        return when (alg) {
            CoseAlgorithm.ES256 -> "SHA256withECDSA"
            CoseAlgorithm.RS256 -> "SHA256withRSA"
            CoseAlgorithm.EdDSA -> "Ed25519"
        }
    }
}
