package dev.webauthn.server.crypto

import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public class TrustChainVerifier(
    private val trustAnchorSource: TrustAnchorSource,
    private val certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
) {
    public fun verify(chainDer: List<ByteArray>, aaguid: ByteArray? = null): ValidationResult<Unit> {
        if (chainDer.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Certificate chain is empty")),
            )
        }

        val trustAnchorsDer = trustAnchorSource.findTrustAnchors(aaguid)
        if (trustAnchorsDer.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "No trust anchors found for this authenticator")),
            )
        }

        return if (certificateChainValidator.verify(chainDer, trustAnchorsDer)) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Trust chain validation failed")),
            )
        }
    }

    public fun verifyFallbackSignedByNext(chainDer: List<ByteArray>): ValidationResult<Unit> {
        if (chainDer.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Certificate chain is empty")),
            )
        }

        return if (certificateChainValidator.verifySignedByNext(chainDer)) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Certificate chain validation failed")),
            )
        }
    }
}
