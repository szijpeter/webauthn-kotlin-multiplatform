package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public class CompositeAttestationVerifier(
    signatureVerifier: SignatureVerifier? = null,
    trustAnchorSource: TrustAnchorSource? = null,
    digestService: DigestService = JvmDigestService(),
    cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
    certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    certificateInspector: CertificateInspector = JvmCertificateInspector(),
    certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
) : AttestationVerifier {

    private val trustChainVerifier: TrustChainVerifier? = trustAnchorSource?.let {
        TrustChainVerifier(it, certificateChainValidator)
    }

    private val packedVerifier = signatureVerifier?.let {
        PackedAttestationStatementVerifier(
            signatureVerifier = it,
            trustChainVerifier = trustChainVerifier,
            digestService = digestService,
            certificateSignatureVerifier = certificateSignatureVerifier,
            certificateInspector = certificateInspector,
        )
    }

    private val verifiers = mapOf(
        "none" to NoneAttestationStatementVerifier(),
        // packed handled separately
        "android-key" to AndroidKeyAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
            digestService = digestService,
            certificateSignatureVerifier = certificateSignatureVerifier,
            certificateInspector = certificateInspector,
            certificateChainValidator = certificateChainValidator,
            cosePublicKeyDecoder = cosePublicKeyDecoder,
        ),
        "tpm" to TpmAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
            digestService = digestService,
            certificateSignatureVerifier = certificateSignatureVerifier,
            certificateInspector = certificateInspector,
        ),
        "apple" to AppleAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
            digestService = digestService,
            certificateInspector = certificateInspector,
            cosePublicKeyDecoder = cosePublicKeyDecoder,
        ),
        "android-safetynet" to AndroidSafetyNetAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
            digestService = digestService,
            certificateSignatureVerifier = certificateSignatureVerifier,
            certificateInspector = certificateInspector,
        ),
        "fido-u2f" to FidoU2fAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
            digestService = digestService,
            cosePublicKeyDecoder = cosePublicKeyDecoder,
            cosePublicKeyNormalizer = cosePublicKeyNormalizer,
            certificateSignatureVerifier = certificateSignatureVerifier,
        ),
    )

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationBytes = input.response.attestationObject.bytes()
        if (attestationBytes.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attestationObject", "Attestation object is missing")),
            )
        }

        val parsed = parseAttestationObject(attestationBytes)
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidFormat("attestationObject", "Malformed CBOR")),
            )

        return when (parsed.fmt) {
            "packed" -> packedVerifier?.verify(input)
                ?: ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("attestationObject.fmt", "Packed attestation not supported: no SignatureVerifier configured")),
                )
            else -> verifiers[parsed.fmt]?.verify(input)
                ?: ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("attestationObject.fmt", "Unsupported attestation format: ${parsed.fmt}")),
                )
        }
    }
}
