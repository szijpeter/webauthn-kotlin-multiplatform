package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CoseKeyParser
import dev.webauthn.crypto.ParsedCosePublicKey
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

public class JvmRpIdHasher : RpIdHasher {
    override fun hashRpId(rpId: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
    }
}

public class JvmSignatureVerifier : SignatureVerifier {
    override fun verify(
        algorithm: CoseAlgorithm,
        publicKeyCose: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val parsed = JvmCoseKeyParser(algorithm).parsePublicKey(publicKeyCose)
        val keyFactory = when (parsed.algorithm) {
            CoseAlgorithm.ES256 -> KeyFactory.getInstance("EC")
            CoseAlgorithm.RS256 -> KeyFactory.getInstance("RSA")
            CoseAlgorithm.EdDSA -> KeyFactory.getInstance("Ed25519")
        }

        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(parsed.x509SubjectPublicKeyInfo))

        val signatureInstance = when (parsed.algorithm) {
            CoseAlgorithm.ES256 -> Signature.getInstance("SHA256withECDSA")
            CoseAlgorithm.RS256 -> Signature.getInstance("SHA256withRSA")
            CoseAlgorithm.EdDSA -> Signature.getInstance("Ed25519")
        }

        signatureInstance.initVerify(publicKey)
        signatureInstance.update(data)
        return signatureInstance.verify(signature)
    }
}

public class JvmCoseKeyParser(
    private val defaultAlgorithm: CoseAlgorithm = CoseAlgorithm.ES256,
) : CoseKeyParser {
    override fun parsePublicKey(coseKey: ByteArray): ParsedCosePublicKey {
        // V1 baseline: parser currently accepts SPKI input as-is.
        return ParsedCosePublicKey(
            algorithm = defaultAlgorithm,
            x509SubjectPublicKeyInfo = coseKey,
        )
    }
}

public class StrictAttestationVerifier(
    signatureVerifier: SignatureVerifier? = null,
) : AttestationVerifier {
    private val noneVerifier = NoneAttestationStatementVerifier()
    private val packedVerifier = signatureVerifier?.let { PackedAttestationStatementVerifier(it) }

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationBytes = input.response.attestationObject.bytes()
        if (attestationBytes.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = "attestationObject",
                        message = "Attestation object must be present in strict mode",
                    ),
                ),
            )
        }

        // Parse just to determine fmt for dispatching
        val parsed = parseAttestationObject(attestationBytes)
            ?: return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidFormat(
                        field = "attestationObject",
                        message = "Attestation object is not valid CBOR",
                    ),
                ),
            )

        return when (parsed.fmt) {
            "none" -> noneVerifier.verify(input)
            "packed" -> packedVerifier?.verify(input)
                ?: ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidValue(
                            field = "attestationObject.fmt",
                            message = "Packed attestation not supported: no SignatureVerifier configured",
                        ),
                    ),
                )
            else -> ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = "attestationObject.fmt",
                        message = "Unsupported attestation format: ${parsed.fmt}",
                    ),
                ),
            )
        }
    }
}
