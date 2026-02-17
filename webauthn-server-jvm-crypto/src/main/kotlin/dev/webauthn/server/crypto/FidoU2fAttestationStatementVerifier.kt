package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public class FidoU2fAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
    private val digestService: DigestService = JvmDigestService(),
    private val cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    private val cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
    private val certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    private val certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
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

        // 1. Verify that x5c contains at least one element. Let attCert be the first element.
        val attCertDer = x5c[0]

        val attestedData = input.response.attestedCredentialData

        val clientDataHash = digestService.sha256(input.response.clientDataJson.bytes())
        
        // publicKeyU2F must be 65 bytes: 0x04 || X || Y
        val publicKeyU2F = extractRawPublicKey(attestedData.cosePublicKey)
            ?: return failure("cosePublicKey", "Could not extract U2F public key from COSE")

        val verificationData = concat(
            byteArrayOf(0x00),
            input.response.rawAuthenticatorData.rpIdHash,
            clientDataHash,
            attestedData.credentialId.value.bytes(),
            publicKeyU2F
        )

        if (!certificateSignatureVerifier.verify(CoseAlgorithm.ES256, attCertDer, verificationData, sig)) {
            return failure("sig", "Invalid fido-u2f attestation signature")
        }

        // 4. Optionally verify trust anchor
        if (trustAnchorSource != null) {
            val chainVerifier = TrustChainVerifier(trustAnchorSource, certificateChainValidator)
            val result = chainVerifier.verify(x5c, attestedData.aaguid)
            if (result is ValidationResult.Invalid) return result
        }

        return ValidationResult.Valid(Unit)
    }

    private fun extractRawPublicKey(coseKey: ByteArray): ByteArray? {
        val material = cosePublicKeyDecoder.decode(coseKey) ?: return null
        if (material.kty != 2L) return null // Only EC2 (P-256) supported for U2F
        return cosePublicKeyNormalizer.toUncompressedEcPoint(material)
    }

    private fun failure(field: String, message: String) = ValidationResult.Invalid(
        listOf(WebAuthnValidationError.InvalidValue("attestationObject.$field", message))
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
