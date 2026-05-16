package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/**
 * Verifies the "none" attestation statement format per WebAuthn L3 §8.7.
 *
 * For `fmt: "none"`, the attestation statement (`attStmt`) must be an empty CBOR map.
 */
public class NoneAttestationStatementVerifier : AttestationVerifier {
    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationBytes = input.response.attestationObject.bytes()
        if (attestationBytes.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = "attestationObject",
                        message = "Attestation object must be present",
                    ),
                ),
            )
        }

        val parsed = parseAttestationObject(attestationBytes)
            ?: return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidFormat(
                        field = "attestationObject",
                        message = "Attestation object is not valid CBOR",
                    ),
                ),
            )

        if (parsed.fmt != "none") {
            return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = "attestationObject.fmt",
                        message = "Unsupported attestation format: ${parsed.fmt}",
                    ),
                ),
            )
        }

        if (parsed.attStmtEntryCount != 0) {
            return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = "attestationObject.attStmt",
                        message = "attStmt must be empty for fmt \"none\"",
                    ),
                ),
            )
        }

        return ValidationResult.Valid(Unit)
    }
}
