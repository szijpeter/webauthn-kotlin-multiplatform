package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public class FidoU2fAttestationStatementVerifier(
    private val trustChainVerifier: TrustChainVerifier? = null,
) : AttestationVerifier {

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationBytes = input.response.attestationObject.bytes()
        val parsed = parseAttestationObject(attestationBytes)
            ?: return failure("attestationObject", "Malformed CBOR")

        if (parsed.fmt != "fido-u2f") {
            return failure("fmt", "Expected fido-u2f but got ${parsed.fmt}")
        }

        val sig = parsed.sig ?: return failure("sig", "Missing signature")
        val x5c = parsed.x5c ?: return failure("x5c", "Missing attestation certificate")
        if (x5c.isEmpty()) return failure("x5c", "Attestation certificate list is empty")

        val attCertDer = x5c[0]
        val attestedData = input.response.attestedCredentialData
        val clientDataHash = SignumPrimitives.sha256(input.response.clientDataJson.bytes())

        val publicKeyU2F = extractRawPublicKey(attestedData.cosePublicKey)
            ?: return failure("cosePublicKey", "Could not extract U2F public key from COSE")

        val verificationData = concat(
            byteArrayOf(0x00),
            input.response.rawAuthenticatorData.rpIdHash,
            clientDataHash,
            attestedData.credentialId.value.bytes(),
            publicKeyU2F,
        )

        if (!SignumPrimitives.verifyWithCertificate(CoseAlgorithm.ES256, attCertDer, verificationData, sig)) {
            return failure("sig", "Invalid fido-u2f attestation signature")
        }

        if (trustChainVerifier != null) {
            val result = trustChainVerifier.verify(x5c, attestedData.aaguid)
            if (result is ValidationResult.Invalid) return result
        }

        return ValidationResult.Valid(Unit)
    }

    private fun extractRawPublicKey(coseKey: ByteArray): ByteArray? {
        val material = SignumPrimitives.decodeCoseMaterial(coseKey) ?: return null
        if (material.kty != 2L) return null
        return SignumPrimitives.toUncompressedEcPoint(material)
    }

    private fun failure(field: String, message: String) = ValidationResult.Invalid(
        listOf(WebAuthnValidationError.InvalidValue("attestationObject.$field", message)),
    )

    private fun concat(vararg chunks: ByteArray): ByteArray {
        val size = chunks.sumOf { it.size }
        val result = ByteArray(size)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(result, destinationOffset = offset)
            offset += chunk.size
        }
        return result
    }
}
