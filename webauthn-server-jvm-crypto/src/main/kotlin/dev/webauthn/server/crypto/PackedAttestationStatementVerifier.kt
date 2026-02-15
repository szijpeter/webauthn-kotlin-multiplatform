package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

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
        val clientDataHash = MessageDigest.getInstance("SHA-256")
            .digest(input.response.clientDataJson.bytes())
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

        val attCert = try {
            val factory = CertificateFactory.getInstance("X.509")
            factory.generateCertificate(attCertDer.inputStream()) as X509Certificate
        } catch (_: Exception) {
            return invalid("attestationObject.attStmt.x5c", "Invalid X.509 certificate in x5c")
        }

        // Verify the signature using the attCert's public key
        val jcaAlgorithm = when (coseAlgorithm) {
            CoseAlgorithm.ES256 -> "SHA256withECDSA"
            CoseAlgorithm.RS256 -> "SHA256withRSA"
            CoseAlgorithm.EdDSA -> "Ed25519"
        }

        val verified = try {
            val jcaSig = java.security.Signature.getInstance(jcaAlgorithm)
            jcaSig.initVerify(attCert.publicKey)
            jcaSig.update(signatureBase)
            jcaSig.verify(sig)
        } catch (_: Exception) {
            false
        }

        if (!verified) {
            return invalid("attestationObject.attStmt.sig", "Full attestation signature verification failed")
        }

        // Validate attCert subject OU = "Authenticator Attestation"
        val subjectDN = attCert.subjectX500Principal.name
        if (!subjectDN.contains("OU=Authenticator Attestation")) {
            return invalid(
                "attestationObject.attStmt.x5c",
                "attCert subject must contain OU=Authenticator Attestation",
            )
        }

        return ValidationResult.Valid(Unit)
    }

    private fun coseAlgorithmFromCode(code: Int): CoseAlgorithm? {
        return CoseAlgorithm.entries.find { it.code == code }
    }

    private fun invalid(field: String, message: String): ValidationResult<Unit> {
        return ValidationResult.Invalid(
            listOf(WebAuthnValidationError.InvalidValue(field = field, message = message)),
        )
    }
}
