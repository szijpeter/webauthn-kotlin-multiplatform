package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Arrays

import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.TrustAnchorSource

internal class AndroidKeyAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
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

        // 1. Verify that "alg", "sig", and "x5c" are present
        if (attestationObject.alg == null || attestationObject.sig == null || attestationObject.x5c.isNullOrEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "alg, sig, and x5c are required")),
            )
        }

        // 2. Verify that x5c array contains at least one certificate
        val x5c = attestationObject.x5c!!
        val certFactory = CertificateFactory.getInstance("X.509")
        val certs = try {
            x5c.map { bytes ->
                certFactory.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
            }
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse certificates: ${e.message}")),
            )
        }
        
        val leafCert = certs.first()

        // 3. Verify signature over authData + clientDataHash
        val clientDataHash = java.security.MessageDigest.getInstance("SHA-256").digest(input.response.clientDataJson.bytes())
        
        val signedData = attestationObject.authDataBytes!! + clientDataHash

        try {
            val signature = java.security.Signature.getInstance(jcaParams(attestationObject.alg!!))
            signature.initVerify(leafCert.publicKey)
            signature.update(signedData)
            if (!signature.verify(attestationObject.sig)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("sig", "Invalid signature")),
                )
            }
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("sig", "Signature verification error: ${e.message}")),
            )
        }
        
        // 4. Verify certificate chain
        if (trustAnchorSource != null) {
            val chainVerifier = TrustChainVerifier(trustAnchorSource)
            // AAGUID for android-key is in checked later in extension or via authData.
            // Android Key Attestation doesn't strictly depend on AAGUID for root selection (it's Google Root).
            // But we can pass it if we have it from authData.
            // Actually, AttestedCredentialData has AAGUID.
            val aaguid = input.response.attestedCredentialData.aaguid
            val chainResult = chainVerifier.verify(certs, aaguid)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        } else {
             // Fallback to basic integrity check if no trust source provided
            try {
                // Verify each cert is signed by the next issuer
                for (i in 0 until certs.size - 1) {
                    val subject = certs[i]
                    val issuer = certs[i + 1]
                    subject.verify(issuer.publicKey)
                }
            } catch (e: Exception) {
                 return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("x5c", "Certificate chain validation failed: ${e.message}")),
                )
            }
        }

        // 5. Verify Android Key Attestation Extension
        // OID: 1.3.6.1.4.1.11129.2.1.17
        val extensionOid = "1.3.6.1.4.1.11129.2.1.17"
        val extensionVal = leafCert.getExtensionValue(extensionOid)
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Android Key Attestation extension missing")),
            )

        val metadata = CoseToSpkiConverter.parseCoseKey(input.response.attestedCredentialData.cosePublicKey)
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("coseKey", "Failed to parse COSE key")),
            )

        try {
            // getExtensionValue returns OCTET STRING (DER encoded) wrapping the value
            val outerParser = DerParser(extensionVal)
            val seqBytes = outerParser.readOctetString()

            val parser = DerParser(seqBytes)
            val sequence = parser.readSequence() // KeyDescription SEQUENCE

            // AttestationVersion (INTEGER)
            sequence.readInteger()
            // AttestationSecurityLevel (ENUMERATED)
            sequence.readInteger()
            // KeymasterVersion (INTEGER)
            sequence.readInteger()
            // KeymasterSecurityLevel (ENUMERATED)
            sequence.readInteger()
            // AttestationChallenge (OCTET STRING)
            val challenge = sequence.readOctetString()

            // Verify attestationChallenge matches clientDataHash
            if (!Arrays.equals(challenge, clientDataHash)) {
                 return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("attestationChallenge", "Challenge mismatch in attestation certificate")),
                )
            }

            // UniqueId (OCTET STRING)
            sequence.readOctetString()

            // softwareEnforced (AuthorizationList)
            val swEnforcedSeq = sequence.readSequence()
            val swTags = parseAuthorizationList(swEnforcedSeq)

            // teeEnforced (AuthorizationList)
            val teeEnforcedSeq = sequence.readSequence()
            val teeTags = parseAuthorizationList(teeEnforcedSeq)

            // Combined check: attributes can be in either software or tee enforced lists
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

    private fun checkKeyRequirements(tags: Map<Int, ByteArray>, key: CoseKeyMetadata) {
        if (tags.containsKey(TAG_ALL_APPLICATIONS)) {
            throw IllegalArgumentException("Key is not restricted to this application (allApplications present)")
        }

        // [1] purpose: SET OF INTEGER
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

        // [2] algorithm: INTEGER
        val alg = parseIntTag(tags[TAG_ALGORITHM], "Key algorithm missing")

        // [3] keySize: INTEGER
        val size = parseIntTag(tags[TAG_KEY_SIZE], "Key size missing")

        // [5] digest: SET OF INTEGER
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

        // [702] origin: INTEGER
        val origin = parseIntTag(tags[TAG_ORIGIN], "Key origin missing")
        if (origin != KM_ORIGIN_GENERATED) {
            throw IllegalArgumentException("Key origin is not GENERATED (found $origin)")
        }

        // Validate against COSE key
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

    private fun jcaParams(alg: Long): String {
        return when (alg) {
            -7L -> "SHA256withECDSA" // ES256
            -257L -> "SHA256withRSA" // RS256
            -8L -> "Ed25519" // EdDSA
            else -> throw IllegalArgumentException("Unsupported algorithm: $alg")
        }
    }
}
