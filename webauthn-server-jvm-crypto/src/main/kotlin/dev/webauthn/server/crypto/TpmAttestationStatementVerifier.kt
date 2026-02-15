package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
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
        if (attestationObject.ver != "2.0") {
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


        val alg = attestationObject.alg ?: -7 // Default ES256 if missing? But map can have it. If missing, COSE alg usually inferred or required.
        // Usually alg is present in attStmt for TPM.
        if (attestationObject.alg == null) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("alg", "Algorithm identifier missing")),
            )
        }

        try {
            val signature = java.security.Signature.getInstance(jcaParams(alg!!))
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

        // 6. Verify AIK certificate constraints (extendedKeyUsage, etc) - optional/advanced step, maybe later.
        // Prompt only asked for checks implemented above.
        
        return ValidationResult.Valid(Unit)
    }

    private fun jcaParams(alg: Long): String {
        return when (alg) {
            -7L -> "SHA256withECDSA" // ES256
            -257L -> "SHA256withRSA" // RS256
            -8L -> "Ed25519" // EdDSA
            else -> throw IllegalArgumentException("Unsupported algorithm: $alg")
        }
    }
}
