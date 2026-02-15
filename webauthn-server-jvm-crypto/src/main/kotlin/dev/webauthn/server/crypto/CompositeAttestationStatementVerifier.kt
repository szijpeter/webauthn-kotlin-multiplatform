package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public class CompositeAttestationVerifier(
    signatureVerifier: SignatureVerifier? = null,
    trustAnchorSource: TrustAnchorSource? = null,
) : AttestationVerifier {

    private val packedVerifier = signatureVerifier?.let { PackedAttestationStatementVerifier(it) }
    
    private val verifiers = mapOf(
        "none" to NoneAttestationStatementVerifier(),
        // packed handled separately
        "android-key" to AndroidKeyAttestationStatementVerifier(trustAnchorSource),
        "tpm" to TpmAttestationStatementVerifier(), // TODO: add trust source
        "apple" to AppleAttestationStatementVerifier(), // TODO: add trust source
        "android-safetynet" to AndroidSafetyNetAttestationStatementVerifier(),
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
