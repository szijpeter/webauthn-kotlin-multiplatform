package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.io.ByteArrayInputStream
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

internal class AndroidSafetyNetAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
) : AttestationVerifier {

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        val attestationObject = parseAttestationObject(input.response.attestationObject.bytes())
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("attestationObject", "Malformed CBOR")),
            )

        if (attestationObject.fmt != "android-safetynet") {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("fmt", "Format must be android-safetynet")),
            )
        }

        // 1. Verify response is present
        if (attestationObject.response == null) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "response is required")),
            )
        }

        // 2. Parse JWS
        val jws = attestationObject.response.decodeToString()
        val parts = jws.split(".")
        if (parts.size != 3) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "Invalid JWS format")),
            )
        }

        val headerB64 = parts[0]
        val payloadB64 = parts[1]
        val signatureB64 = parts[2]

        // 3. Verify header (x5c)
        // I need to parse the header JSON to get x5c.
        // Assuming NO JSON lib.
        // Header: {"alg":"RS256","x5c":["MII...","MII..."]}
        val headerJson = String(Base64.getUrlDecoder().decode(headerB64), Charsets.UTF_8)
        
        // Extract x5c strings using regex
        val x5cPattern = "\"x5c\"\\s*:\\s*\\[([^\\]]+)\\]".toRegex()
        val x5cMatch = x5cPattern.find(headerJson)
        if (x5cMatch == null) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "x5c missing in JWS header")),
            )
        }
        
        // Split cert strings. They are quoted strings separated by comma.
        val certsStr = x5cMatch.groupValues[1]
        val certsB64 = certsStr.split(",").map { it.trim().trim('"') }
        
        if (certsB64.isEmpty()) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "No certificates in JWS header")),
            )
        }

        val certFactory = CertificateFactory.getInstance("X.509")
        val certs = mutableListOf<X509Certificate>()
        val leafCert: X509Certificate
        try {
            for (certB64 in certsB64) {
                val certBytes = Base64.getDecoder().decode(certB64)
                val cert = certFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
                certs.add(cert)
            }
            leafCert = certs[0]
        } catch (e: Exception) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to decode/parse certificate: ${e.message}")),
            )
        }

        if (trustAnchorSource != null) {
            val chainVerifier = TrustChainVerifier(trustAnchorSource)
            // SafetyNet does not use AAGUID for trust selection
            val chainResult = chainVerifier.verify(certs, null)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        }
        
        // 4. Verify signature
        // RS256 usually.
        // Need to check "alg" in header? Assuming RS256 for SafetyNet.
        try {
            val sigBytes = Base64.getUrlDecoder().decode(signatureB64)
            val signedData = "$headerB64.$payloadB64".toByteArray(Charsets.UTF_8)
            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(leafCert.publicKey)
            signature.update(signedData)
            if (!signature.verify(sigBytes)) {
                 return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("response", "JWS signature verification failed")),
                )
            }
        } catch (e: Exception) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "Signature verification error: ${e.message}")),
            )
        }

        // 5. Verify payload
        val payloadJson = String(Base64.getUrlDecoder().decode(payloadB64), Charsets.UTF_8)
        
        // Extract nonce
        val noncePattern = "\"nonce\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        val nonceMatch = noncePattern.find(payloadJson)
        if (nonceMatch == null) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("nonce", "Nonce missing in payload")),
            )
        }
        val jwsNonceB64 = nonceMatch.groupValues[1]
        
        // Calculate expected nonce = SHA256(authData || clientDataHash)
        val clientDataHash = java.security.MessageDigest.getInstance("SHA-256").digest(input.response.clientDataJson.bytes())
        val expectedNonce = java.security.MessageDigest.getInstance("SHA-256").digest(attestationObject.authDataBytes!! + clientDataHash)
        // SafetyNet nonce is base64 of the hash? Or base64url? Or hex? Or raw?
        // Spec says: "The nonce attribute contains the Base64 encoding of the SHA-256 hash..."
        // Typically Base64 (legacy) or Base64Url? SafetyNet uses Base64 (standard).
        // Let's try matching decoded bytes.
        
        val jwsNonceBytes = try {
            Base64.getDecoder().decode(jwsNonceB64)
        } catch (e: IllegalArgumentException) {
            // Try Url decoder if standard fails?
            Base64.getUrlDecoder().decode(jwsNonceB64)
        }

        if (!java.util.Arrays.equals(jwsNonceBytes, expectedNonce)) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("nonce", "Nonce mismatch")),
            )
        }

        // Check ctsProfileMatch
        if (!payloadJson.contains("\"ctsProfileMatch\":true") && !payloadJson.contains("\"ctsProfileMatch\": true")) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("ctsProfileMatch", "Device not compatible (ctsProfileMatch false)")),
            )
        }

        return ValidationResult.Valid(Unit)
    }
}
