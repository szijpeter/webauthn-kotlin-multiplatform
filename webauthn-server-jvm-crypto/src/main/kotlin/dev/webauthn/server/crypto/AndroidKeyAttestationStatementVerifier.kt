package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.coseAlgorithmFromCode
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyMaterial
import dev.webauthn.crypto.DigestService
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.math.BigInteger
import java.util.Arrays

internal class AndroidKeyAttestationStatementVerifier(
    private val trustChainVerifier: TrustChainVerifier? = null,
    private val digestService: DigestService = JvmDigestService(),
    private val certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    private val certificateInspector: CertificateInspector = JvmCertificateInspector(),
    private val certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
    private val cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
) : AttestationVerifier {
    companion object {
        private const val TAG_PURPOSE = 0xA1
        private const val TAG_ALGORITHM = 0xA2
        private const val TAG_KEY_SIZE = 0xA3
        private const val TAG_DIGEST = 0xA5
        private const val TAG_EC_CURVE = 0xAA
        private const val TAG_ALL_APPLICATIONS = 0xBF8458
        private const val TAG_ORIGIN = 0xBF853E

        private const val KM_PURPOSE_SIGN = 2
        private const val KM_ALGORITHM_RSA = 1
        private const val KM_ALGORITHM_EC = 3
        private const val KM_DIGEST_SHA_2_256 = 4
        private const val KM_EC_CURVE_P_256 = 1
        private const val KM_ORIGIN_GENERATED = 0
    }

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationObject = parseAttestationObject(input.response.attestationObject.bytes())
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("attestationObject", "Malformed CBOR")),
            )

        if (attestationObject.fmt != "android-key") {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("fmt", "Format must be android-key")),
            )
        }

        if (attestationObject.alg == null || attestationObject.sig == null || attestationObject.x5c.isNullOrEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "alg, sig, and x5c are required")),
            )
        }

        val certsDer = attestationObject.x5c
        val leafCertDer = certsDer.first()
        val authData = attestationObject.authDataBytes
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("authData", "authData is required")),
            )

        val clientDataHash = digestService.sha256(input.response.clientDataJson.bytes())
        val signedData = authData + clientDataHash
        val coseAlgorithm = coseAlgorithmFromCode(attestationObject.alg.toInt())
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("alg", "Unsupported algorithm: ${attestationObject.alg}")),
            )
        val signatureValid = certificateSignatureVerifier.verify(
            algorithm = coseAlgorithm,
            certificateDer = leafCertDer,
            data = signedData,
            signature = attestationObject.sig,
        )
        if (!signatureValid) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("sig", "Invalid signature")),
            )
        }

        if (trustChainVerifier != null) {
            val aaguid = input.response.attestedCredentialData.aaguid
            val chainResult = trustChainVerifier.verify(certsDer, aaguid)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        } else if (!certificateChainValidator.verifySignedByNext(certsDer)) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Certificate chain validation failed")),
            )
        }

        val extensionOid = "1.3.6.1.4.1.11129.2.1.17"
        val extensionVal = try {
            certificateInspector.extensionValue(leafCertDer, extensionOid)
        } catch (_: Exception) {
            null
        } ?: return ValidationResult.Invalid(
            listOf(WebAuthnValidationError.MissingValue("x5c", "Android Key Attestation extension missing")),
        )

        val metadata = cosePublicKeyDecoder.decode(input.response.attestedCredentialData.cosePublicKey)
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("coseKey", "Failed to parse COSE key")),
            )

        try {
            val outerParser = DerParser(extensionVal)
            val seqBytes = outerParser.readOctetString()

            val parser = DerParser(seqBytes)
            val sequence = parser.readSequence()

            sequence.readInteger() // attestationVersion
            sequence.readInteger() // attestationSecurityLevel
            sequence.readInteger() // keymasterVersion
            sequence.readInteger() // keymasterSecurityLevel
            val challenge = sequence.readOctetString()

            if (!Arrays.equals(challenge, clientDataHash)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("attestationChallenge", "Challenge mismatch in attestation certificate")),
                )
            }

            sequence.readOctetString() // uniqueId
            val swEnforcedSeq = sequence.readSequence()
            val swTags = parseAuthorizationList(swEnforcedSeq)
            val teeEnforcedSeq = sequence.readSequence()
            val teeTags = parseAuthorizationList(teeEnforcedSeq)

            val allTags = swTags + teeTags
            checkKeyRequirements(allTags, metadata)
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse Android Key Attestation extension: ${e.message}")),
            )
        }

        return ValidationResult.Valid(Unit)
    }

    private fun parseAuthorizationList(parser: DerParser): Map<Int, ByteArray> {
        val tags = mutableMapOf<Int, ByteArray>()
        while (!parser.isExhausted) {
            val header = parser.readNextTLV()
            tags[header.tag] = header.value
        }
        return tags
    }

    private fun checkKeyRequirements(tags: Map<Int, ByteArray>, key: CosePublicKeyMaterial) {
        if (tags.containsKey(TAG_ALL_APPLICATIONS)) {
            throw IllegalArgumentException("Key is not restricted to this application (allApplications present)")
        }

        val purposeBytes = tags[TAG_PURPOSE] ?: throw IllegalArgumentException("Key purpose missing")
        val purposeSet = DerParser(purposeBytes).readSet()
        var hasSignPurpose = false
        while (!purposeSet.isExhausted) {
            if (BigInteger(purposeSet.readInteger()).toInt() == KM_PURPOSE_SIGN) {
                hasSignPurpose = true
            }
        }
        if (!hasSignPurpose) {
            throw IllegalArgumentException("Key purpose does not contain SIGN")
        }

        val alg = parseIntTag(tags[TAG_ALGORITHM], "Key algorithm missing")
        val size = parseIntTag(tags[TAG_KEY_SIZE], "Key size missing")

        val digestBytes = tags[TAG_DIGEST] ?: throw IllegalArgumentException("Key digest missing")
        val digestSet = DerParser(digestBytes).readSet()
        var hasSha256 = false
        while (!digestSet.isExhausted) {
            if (BigInteger(digestSet.readInteger()).toInt() == KM_DIGEST_SHA_2_256) {
                hasSha256 = true
            }
        }
        if (!hasSha256) {
            throw IllegalArgumentException("Key digest does not contain SHA-256")
        }

        val origin = parseIntTag(tags[TAG_ORIGIN], "Key origin missing")
        if (origin != KM_ORIGIN_GENERATED) {
            throw IllegalArgumentException("Key origin is not GENERATED (found $origin)")
        }

        when (key.kty) {
            2L -> {
                if (alg != KM_ALGORITHM_EC) {
                    throw IllegalArgumentException("Attestation alg $alg does not match EC key")
                }
                if (size != 256) {
                    throw IllegalArgumentException("Attestation key size $size != 256 for EC")
                }
                val curve = parseIntTag(tags[TAG_EC_CURVE], "Attestation curve missing for EC key")
                if (curve != KM_EC_CURVE_P_256) {
                    throw IllegalArgumentException("Attestation curve $curve is not P-256")
                }
            }
            3L -> {
                if (alg != KM_ALGORITHM_RSA) {
                    throw IllegalArgumentException("Attestation alg $alg does not match RSA key")
                }
                val modulus = key.n ?: throw IllegalArgumentException("RSA modulus missing in COSE key")
                val modulusBits = BigInteger(1, modulus).bitLength()
                if (size != modulusBits) {
                    throw IllegalArgumentException("Attestation key size $size does not match RSA modulus size $modulusBits")
                }
            }
            else -> throw IllegalArgumentException("Unsupported COSE key type for Android Key attestation: ${key.kty}")
        }
    }

    private fun parseIntTag(value: ByteArray?, missingMessage: String): Int {
        val bytes = value ?: throw IllegalArgumentException(missingMessage)
        return BigInteger(DerParser(bytes).readInteger()).toInt()
    }
}
