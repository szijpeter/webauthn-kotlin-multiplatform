package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.util.Arrays

internal class AppleAttestationStatementVerifier(
    private val trustChainVerifier: TrustChainVerifier? = null,
    private val certificateInspector: JvmCertificateInspector = JvmCertificateInspector(),
) : AttestationVerifier {

    companion object {
        private const val APPLE_EXTENSION_OID = "1.2.840.113635.100.8.2"
    }

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationObject = parseAttestationObject(input.response.attestationObject.bytes())
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("attestationObject", "Malformed CBOR")),
            )

        if (attestationObject.fmt != "apple") {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("fmt", "Format must be apple")),
            )
        }

        if (attestationObject.x5c.isNullOrEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "x5c is required")),
            )
        }

        val certsDer = attestationObject.x5c
        val leafCertDer = certsDer[0]

        if (trustChainVerifier != null) {
            val aaguid = input.response.attestedCredentialData.aaguid
            val chainResult = trustChainVerifier.verify(certsDer, aaguid)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        }

        val authDataBytes = attestationObject.authDataBytes
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("authData", "authData is required")),
            )
        val clientDataHash = SignumPrimitives.sha256(input.response.clientDataJson.bytes())
        val nonce = SignumPrimitives.sha256(authDataBytes + clientDataHash)

        val extensionValue = try {
            certificateInspector.extensionValue(leafCertDer, APPLE_EXTENSION_OID)
        } catch (_: Exception) {
            null
        }
        if (extensionValue == null) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Apple extension not found")),
            )
        }

        try {
            val outerParser = DerParser(extensionValue)
            val innerBytes = outerParser.readOctetString()
            val innerParser = DerParser(innerBytes)
            val extensionNonce = innerParser.readOctetString()
            if (!Arrays.equals(extensionNonce, nonce)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("x5c", "Certificate nonce mismatch")),
                )
            }
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse Apple extension: ${e.message}")),
            )
        }

        val credPubKeyBytes = input.response.attestedCredentialData.cosePublicKey
        if (credPubKeyBytes.isNotEmpty()) {
            val metadata = SignumPrimitives.decodeCoseMaterial(credPubKeyBytes)
            if (metadata != null && metadata.kty == 2L) {
                val certMetadata = try {
                    certificateInspector.inspect(leafCertDer)
                } catch (e: Exception) {
                    return ValidationResult.Invalid(
                        listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to inspect certificate: ${e.message}")),
                    )
                }
                if (certMetadata.ecPublicKeyX != null && certMetadata.ecPublicKeyY != null) {
                    if (!matchesEcKey(metadata.x, metadata.y, certMetadata.ecPublicKeyX, certMetadata.ecPublicKeyY)) {
                        return ValidationResult.Invalid(
                            listOf(WebAuthnValidationError.InvalidValue("pubKey", "Public key mismatch")),
                        )
                    }
                }
            }
        }

        return ValidationResult.Valid(Unit)
    }

    private fun matchesEcKey(
        coseX: ByteArray?,
        coseY: ByteArray?,
        certX: ByteArray?,
        certY: ByteArray?,
    ): Boolean {
        if (coseX == null || coseY == null || certX == null || certY == null) {
            return false
        }
        return Arrays.equals(coseX, certX) && Arrays.equals(coseY, certY)
    }
}
