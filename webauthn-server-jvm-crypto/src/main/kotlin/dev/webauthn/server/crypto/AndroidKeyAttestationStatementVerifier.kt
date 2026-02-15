package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Arrays

internal class AndroidKeyAttestationStatementVerifier : AttestationVerifier {

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
        
        // 4. Verify certificate chain (basic)
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

        // 5. Verify Android Key Attestation Extension
        // OID: 1.3.6.1.4.1.11129.2.1.17
        val extensionOid = "1.3.6.1.4.1.11129.2.1.17"
        val extensionVal = leafCert.getExtensionValue(extensionOid)
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Android Key Attestation extension missing")),
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

        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse Android Key Attestation extension: ${e.message}")),
            )
        }

        return ValidationResult.Valid(Unit)
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
