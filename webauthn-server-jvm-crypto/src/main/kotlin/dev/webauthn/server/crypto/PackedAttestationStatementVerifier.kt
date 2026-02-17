package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.coseAlgorithmFromCode
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/**
 * Verifies the "packed" attestation statement format per WebAuthn L3 §8.2.
 *
 * Supports:
 * - **Self-attestation**: `sig` verified using the credential's own public key
 * - **Full attestation** (`x5c`): `sig` verified using the attestation certificate's public key
 * - **ECDAA**: rejected (not supported in Level 3)
 */
public class PackedAttestationStatementVerifier(
    private val signatureVerifier: SignatureVerifier,
    private val digestService: DigestService = JvmDigestService(),
    private val certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    private val certificateInspector: CertificateInspector = JvmCertificateInspector(),
) : AttestationVerifier {

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationBytes = input.response.attestationObject.bytes()
        if (attestationBytes.isEmpty()) {
            return invalid("attestationObject", "Attestation object must be present")
        }

        val parsed = parseAttestationObject(attestationBytes)
            ?: return invalid("attestationObject", "Attestation object is not valid CBOR")

        if (parsed.fmt != "packed") {
            return invalid("attestationObject.fmt", "Expected packed format, got: ${parsed.fmt}")
        }

        val alg = parsed.alg
            ?: return invalid("attestationObject.attStmt.alg", "Missing alg in packed attStmt")
        val sig = parsed.sig
            ?: return invalid("attestationObject.attStmt.sig", "Missing sig in packed attStmt")
        val authDataBytes = parsed.authDataBytes
            ?: return invalid("attestationObject.authData", "Missing authData in attestation object")

        // Reject ECDAA
        if (parsed.ecdaaKeyId != null) {
            return invalid("attestationObject.attStmt.ecdaaKeyId", "ECDAA is not supported")
        }

        // Build signatureBase = authData || SHA-256(clientDataJSON)
        val clientDataHash = digestService.sha256(input.response.clientDataJson.bytes())
        val signatureBase = authDataBytes + clientDataHash

        val coseAlgorithm = coseAlgorithmFromCode(alg.toInt())
            ?: return invalid("attestationObject.attStmt.alg", "Unsupported COSE algorithm: $alg")

        return if (parsed.x5c != null && parsed.x5c.isNotEmpty()) {
            verifyFullAttestation(parsed.x5c, sig, signatureBase, coseAlgorithm, input)
        } else {
            verifySelfAttestation(sig, signatureBase, coseAlgorithm, input)
        }
    }

    private fun verifySelfAttestation(
        sig: ByteArray,
        signatureBase: ByteArray,
        coseAlgorithm: CoseAlgorithm,
        input: RegistrationValidationInput,
    ): ValidationResult<Unit> {
        // For self-attestation, alg must match the credential's algorithm
        val credentialPublicKey = input.response.attestedCredentialData.cosePublicKey

        val verified = try {
            signatureVerifier.verify(
                algorithm = coseAlgorithm,
                publicKeyCose = credentialPublicKey,
                data = signatureBase,
                signature = sig,
            )
        } catch (_: Exception) {
            false
        }

        return if (verified) {
            ValidationResult.Valid(Unit)
        } else {
            invalid("attestationObject.attStmt.sig", "Self-attestation signature verification failed")
        }
    }

    private fun verifyFullAttestation(
        x5c: List<ByteArray>,
        sig: ByteArray,
        signatureBase: ByteArray,
        coseAlgorithm: CoseAlgorithm,
        input: RegistrationValidationInput,
    ): ValidationResult<Unit> {
        // Extract the leaf certificate (attCert)
        val attCertDer = x5c.firstOrNull()
            ?: return invalid("attestationObject.attStmt.x5c", "x5c chain is empty")

        val certMetadata = try {
            certificateInspector.inspect(attCertDer)
        } catch (_: Exception) {
            return invalid("attestationObject.attStmt.x5c", "Invalid X.509 certificate in x5c")
        }

        val verified = certificateSignatureVerifier.verify(
            algorithm = coseAlgorithm,
            certificateDer = attCertDer,
            data = signatureBase,
            signature = sig,
        )
        if (!verified) {
            return invalid("attestationObject.attStmt.sig", "Full attestation signature verification failed")
        }

        // Validate attCert subject OU = "Authenticator Attestation"
        val subjectDN = certMetadata.subjectDistinguishedName
        if (!subjectDN.contains("OU=Authenticator Attestation")) {
            return invalid(
                "attestationObject.attStmt.x5c",
                "attCert subject must contain OU=Authenticator Attestation",
            )
        }

        // Verify AAGUID if extension present and authData has it (AT flag set)
        // flags at offset 32. AT flag is 0x40.
        val flags = signatureBase[32]
        val hasAt = (flags.toInt() and 0x40) != 0
        
        if (hasAt && signatureBase.size >= 53) {
             val aaguid = signatureBase.copyOfRange(37, 37 + 16)
             val aaguidCheck = AaguidMismatchVerifier.verify(attCertDer, aaguid, certificateInspector)
             if (aaguidCheck is ValidationResult.Invalid) {
                 return aaguidCheck
             }
        }
        
        return ValidationResult.Valid(Unit)
    }

    private fun invalid(field: String, message: String): ValidationResult<Unit> {
        return ValidationResult.Invalid(
            listOf(WebAuthnValidationError.InvalidValue(field = field, message = message)),
        )
    }
}
