package dev.webauthn.server.crypto

import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.security.cert.X509Certificate
import java.util.Arrays

internal object AaguidMismatchVerifier {
    private const val AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4" // id-fido-gen-ce-aaguid

    fun verify(cert: X509Certificate, aaguid: ByteArray): ValidationResult<Unit> {
        val extensionValue = cert.getExtensionValue(AAGUID_OID) ?: return ValidationResult.Valid(Unit) // Not present, skip check

        // Parse extension value (OCTET STRING containing AAGUID OCTET STRING?)
        // Spec: "OCTET STRING containing the AAGUID bytes."
        // Similar to Apple: double OCTET STRING wrap usually.
        // FIDO U2F Metadata Statement §3.1.11.
        // Usually: OCTET STRING (containing 16 bytes).
        // Let's try parsing.
        
        try {
            val outerParser = DerParser(extensionValue)
            val innerBytes = outerParser.readOctetString()
            
            // Wait, is it double wrapped?
            // "The extension value is an OCTET STRING..."
            // Usually this means value in certificate is DER encoded OCTET STRING.
            // When unwrapped (readOctetString), you get value bytes.
            // Are value bytes RAW AAGUID or OCTET STRING(AAGUID)?
            // Usually ASN.1 defined as `OCTET STRING`.
            // So extension value (DER) -> OCTET STRING (tag 04, len, content).
            // Content IS the OCTET STRING data.
            // If data IS the AAGUID, then done.
            // If data is `OCTET STRING(AAGUID)`, then unwrap again.
            // Standard FIDO extensions use raw value inside OCTET STRING wrapper?
            // "The syntax of the extension value is OCTET STRING."
            // This means the type is OCTET STRING.
            // So `extnValue` (DER encoded) is `04 10 [16 bytes]`.
            // `readOctetString` returns `[16 bytes]`.
            // Let's assume single wrap (standard X.509 extension behavior).
            // BUT: `DerParser` reads TLV.
            // `cert.getExtensionValue` returns `04 10 ...`.
            // `readOctetString` returns content bytes.
            // If content bytes length is 16, it's AAGUID.
            // If content bytes starts with 04 and len is 16, it's double wrapped.
            
            if (innerBytes.size == 16) {
                 if (!Arrays.equals(innerBytes, aaguid)) {
                     return ValidationResult.Invalid(listOf(WebAuthnValidationError.InvalidValue("x5c", "AAGUID in certificate does not match authenticator AAGUID")))
                 }
                 return ValidationResult.Valid(Unit)
            }
            
            // Try double unwrap
            try {
                val innerParser = DerParser(innerBytes)
                val doubleInner = innerParser.readOctetString()
                if (doubleInner.size == 16) {
                    if (!Arrays.equals(doubleInner, aaguid)) {
                        return ValidationResult.Invalid(listOf(WebAuthnValidationError.InvalidValue("x5c", "AAGUID in certificate does not match authenticator AAGUID")))
                    }
                    return ValidationResult.Valid(Unit)
                }
            } catch (e: Exception) {
                // Ignore, was not double wrapped
            }

            // Fallback: raw match failed and unwrap failed or size mismatch
            if (innerBytes.size != 16) {
                 // Maybe it's not AAGUID but something else?
                 // But OID matches AAGUID extension.
                 return ValidationResult.Invalid(listOf(WebAuthnValidationError.InvalidValue("x5c", "Invalid AAGUID extension length: ${innerBytes.size}")))
            }

            return ValidationResult.Valid(Unit)
        } catch (e: Exception) {
            return ValidationResult.Invalid(listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse AAGUID extension: ${e.message}")))
        }
    }
}
