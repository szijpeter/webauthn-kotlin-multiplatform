package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public class CompositeAttestationVerifier internal constructor(
    signatureVerifier: SignatureVerifier? = null,
    trustAnchorSource: TrustAnchorSource? = null,
    certificateChainValidator: JvmCertificateChainValidator = JvmCertificateChainValidator(),
) : AttestationVerifier {

    public constructor(
        signatureVerifier: SignatureVerifier? = null,
        trustAnchorSource: TrustAnchorSource? = null,
    ) : this(
        signatureVerifier = signatureVerifier,
        trustAnchorSource = trustAnchorSource,
        certificateChainValidator = JvmCertificateChainValidator(),
    )

    private val trustChainVerifier: TrustChainVerifier? = trustAnchorSource?.let {
        TrustChainVerifier(it, certificateChainValidator)
    }

    private val packedVerifier = signatureVerifier?.let {
        PackedAttestationStatementVerifier(
            signatureVerifier = it,
            trustChainVerifier = trustChainVerifier,
        )
    }

    private val verifiers = mapOf(
        "none" to NoneAttestationStatementVerifier(),
        "android-key" to AndroidKeyAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
            certificateChainValidator = certificateChainValidator,
        ),
        "tpm" to TpmAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
        ),
        "apple" to AppleAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
        ),
        "android-safetynet" to AndroidSafetyNetAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
        ),
        "fido-u2f" to FidoU2fAttestationStatementVerifier(
            trustChainVerifier = trustChainVerifier,
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
