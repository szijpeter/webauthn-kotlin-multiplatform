package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.coseAlgorithmFromCode
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.nio.ByteBuffer
import java.util.Arrays

internal class TpmAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
    private val digestService: DigestService = JvmDigestService(),
    private val certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    private val certificateInspector: CertificateInspector = JvmCertificateInspector(),
    private val certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
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

        if (attestationObject.fmt != "tpm") {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("fmt", "Format must be tpm")),
            )
        }

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

        val certsDer = attestationObject.x5c
        val leafCertDer = certsDer[0]

        if (trustAnchorSource != null) {
            val chainVerifier = TrustChainVerifier(trustAnchorSource, certificateChainValidator)
            val aaguid = input.response.attestedCredentialData.aaguid
            val chainResult = chainVerifier.verify(certsDer, aaguid)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        }

        val algId = attestationObject.alg
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("alg", "Algorithm identifier missing")),
            )
        val coseAlg = coseAlgorithmFromCode(algId.toInt())
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("alg", "Unsupported algorithm: $algId")),
            )

        val signatureValid = certificateSignatureVerifier.verify(
            algorithm = coseAlg,
            certificateDer = leafCertDer,
            data = attestationObject.certInfo,
            signature = attestationObject.sig,
        )
        if (!signatureValid) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("sig", "Invalid signature over certInfo")),
            )
        }

        try {
            val buffer = ByteBuffer.wrap(attestationObject.certInfo)

            if (buffer.remaining() < 4) throw IllegalArgumentException("certInfo too short")
            val magic = buffer.int
            if (magic != TPM_GENERATED_VALUE) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("certInfo", "Invalid magic: ${Integer.toHexString(magic)}")),
                )
            }

            if (buffer.remaining() < 2) throw IllegalArgumentException("certInfo too short")
            val type = buffer.short
            if (type != TPM_ST_ATTEST_CERTIFY) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("certInfo", "Invalid type: ${Integer.toHexString(type.toInt() and 0xFFFF)}")),
                )
            }

            if (buffer.remaining() < 2) throw IllegalArgumentException("certInfo too short")
            val qsLen = buffer.short.toInt() and 0xFFFF
            if (buffer.remaining() < qsLen) throw IllegalArgumentException("certInfo too short for qualifiedSigner")
            buffer.position(buffer.position() + qsLen)

            if (buffer.remaining() < 2) throw IllegalArgumentException("certInfo too short")
            val edLen = buffer.short.toInt() and 0xFFFF
            if (buffer.remaining() < edLen) throw IllegalArgumentException("certInfo too short for extraData")
            val extraData = ByteArray(edLen)
            buffer.get(extraData)

            val authDataBytes = attestationObject.authDataBytes
                ?: return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.MissingValue("authData", "authData is required")),
                )
            val clientDataHash = digestService.sha256(input.response.clientDataJson.bytes())
            val expectedHash = digestService.sha256(authDataBytes + clientDataHash)
            if (!Arrays.equals(extraData, expectedHash)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("certInfo", "extraData mismatch")),
                )
            }
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("certInfo", "Failed to parse certInfo: ${e.message}")),
            )
        }

        val aikResult = validateAikCert(leafCertDer)
        if (aikResult is ValidationResult.Invalid) {
            return aikResult
        }

        return ValidationResult.Valid(Unit)
    }

    private fun validateAikCert(certificateDer: ByteArray): ValidationResult<Unit> {
        val cert = try {
            certificateInspector.inspect(certificateDer)
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse certificate: ${e.message}")),
            )
        }

        if (cert.version != 3) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate version must be 3")),
            )
        }
        if (cert.subjectDistinguishedName.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate subject must not be empty")),
            )
        }
        if (cert.isCa) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate must not be a CA")),
            )
        }
        if (!cert.extendedKeyUsageOids.contains(OID_TCG_KP_AIK_CERTIFICATE)) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate missing tcg-kp-AIKCertificate EKU")),
            )
        }
        if (cert.criticalExtensionOids.contains("2.5.29.17")) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "AIK certificate SAN extension must not be critical")),
            )
        }

        return ValidationResult.Valid(Unit)
    }
}
