package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.coseAlgorithmFromCode
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/**
 * Verifies the "packed" attestation statement format per WebAuthn L3 §8.2.
 */
public class PackedAttestationStatementVerifier internal constructor(
    private val signatureVerifier: SignatureVerifier,
    private val trustChainVerifier: TrustChainVerifier? = null,
    private val certificateInspector: JvmCertificateInspector = JvmCertificateInspector(),
) : AttestationVerifier {

    public constructor(
        signatureVerifier: SignatureVerifier,
        trustChainVerifier: TrustChainVerifier? = null,
    ) : this(
        signatureVerifier = signatureVerifier,
        trustChainVerifier = trustChainVerifier,
        certificateInspector = JvmCertificateInspector(),
    )

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

        if (parsed.ecdaaKeyId != null) {
            return invalid("attestationObject.attStmt.ecdaaKeyId", "ECDAA is not supported")
        }

        val clientDataHash = SignumPrimitives.sha256(input.response.clientDataJson.bytes())
        val signatureBase = authDataBytes + clientDataHash

        val coseAlgorithm = coseAlgorithmFromCode(alg.toInt())
            ?: return invalid("attestationObject.attStmt.alg", "Unsupported COSE algorithm: $alg")

        return if (!parsed.x5c.isNullOrEmpty()) {
            verifyFullAttestation(parsed.x5c, sig, signatureBase, coseAlgorithm)
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
        val credentialPublicKey = input.response.attestedCredentialData.cosePublicKey
        val material = SignumPrimitives.decodeCoseMaterial(credentialPublicKey)
            ?: return invalid("attestationObject", "Credential COSE public key is malformed or unsupported")
        val keyAlgorithm = SignumPrimitives.coseAlgorithmFromMaterial(material)
            ?: return invalid("attestationObject", "Credential key algorithm is missing or unsupported")

        if (keyAlgorithm != coseAlgorithm) {
            return invalid(
                "attestationObject.attStmt.alg",
                "Attestation algorithm ($coseAlgorithm) does not match credential key algorithm ($keyAlgorithm)",
            )
        }

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
    ): ValidationResult<Unit> {
        val attCertDer = x5c.firstOrNull()
            ?: return invalid("attestationObject.attStmt.x5c", "x5c chain is empty")

        val certMetadata = try {
            certificateInspector.inspect(attCertDer)
        } catch (_: Exception) {
            return invalid("attestationObject.attStmt.x5c", "Invalid X.509 certificate in x5c")
        }

        val verified = SignumPrimitives.verifyWithCertificate(
            algorithm = coseAlgorithm,
            certificateDer = attCertDer,
            data = signatureBase,
            signature = sig,
        )
        if (!verified) {
            return invalid("attestationObject.attStmt.sig", "Full attestation signature verification failed")
        }

        val subjectDN = certMetadata.subjectDistinguishedName
        if (!subjectDN.contains("OU=Authenticator Attestation")) {
            return invalid(
                "attestationObject.attStmt.x5c",
                "attCert subject must contain OU=Authenticator Attestation",
            )
        }

        val flags = signatureBase[32]
        val hasAt = (flags.toInt() and 0x40) != 0

        if (hasAt && signatureBase.size >= 53) {
            val aaguid = signatureBase.copyOfRange(37, 37 + 16)
            val aaguidCheck = AaguidMismatchVerifier.verify(attCertDer, aaguid, certificateInspector)
            if (aaguidCheck is ValidationResult.Invalid) {
                return aaguidCheck
            }
        }

        if (trustChainVerifier != null) {
            val aaguid = if (hasAt && signatureBase.size >= 53) {
                signatureBase.copyOfRange(37, 37 + 16)
            } else {
                null
            }
            val chainResult = trustChainVerifier.verify(x5c, aaguid)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
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
