package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

public class FidoU2fAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
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
        val certFactory = CertificateFactory.getInstance("X.509")
        val attCert = certFactory.generateCertificate(x5c[0].inputStream()) as X509Certificate

        // 2. Extract the public key from attCert.
        // 3. Verify the signature sig over verificationData.
        
        val attestedData = input.response.attestedCredentialData 
            ?: return failure("attestedCredentialData", "Missing attested credential data")

        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(input.response.clientDataJson.bytes())
        
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

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initVerify(attCert.publicKey)
        signature.update(verificationData)

        if (!signature.verify(sig)) {
            return failure("sig", "Invalid fido-u2f attestation signature")
        }

        // 4. Optionally verify trust anchor
        if (trustAnchorSource != null) {
            val trustChain = x5c.map { certFactory.generateCertificate(it.inputStream()) as X509Certificate }
            val chainVerifier = TrustChainVerifier(trustAnchorSource)
            val result = chainVerifier.verify(trustChain, attestedData.aaguid)
            if (result is ValidationResult.Invalid) return result
        }

        return ValidationResult.Valid(Unit)
    }

    private fun extractRawPublicKey(coseKey: ByteArray): ByteArray? {
        val map = parseCoseMap(coseKey) ?: return null
        val kty = map[1L] as? Long ?: return null
        if (kty != 2L) return null // Only EC2 (P-256) supported for U2F
        
        val x = map[-2L] as? ByteArray ?: return null
        val y = map[-3L] as? ByteArray ?: return null
        
        return byteArrayOf(0x04) + x + y
    }

    private fun parseCoseMap(bytes: ByteArray): Map<Long, Any>? {
        var offset = 0
        val header = readCborHeader(bytes, offset) ?: return null
        if (header.majorType != MAJOR_MAP || header.length == null) return null
        offset = header.nextOffset
        
        val result = mutableMapOf<Long, Any>()
        repeat(header.length.toInt()) {
            val keyResult = readCborInt(bytes, offset) ?: return null
            val key = keyResult.first
            offset = keyResult.second
            
            val valueHeader = readCborHeader(bytes, offset) ?: return null
            when (valueHeader.majorType) {
                MAJOR_UNSIGNED_INT, MAJOR_NEGATIVE_INT -> {
                    val v = readCborInt(bytes, offset) ?: return null
                    result[key] = v.first
                    offset = v.second
                }
                MAJOR_BYTE_STRING -> {
                    val v = readCborBytes(bytes, offset) ?: return null
                    result[key] = v.first
                    offset = v.second
                }
                else -> {
                    offset = skipCborItem(bytes, offset) ?: return null
                }
            }
        }
        return result
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
