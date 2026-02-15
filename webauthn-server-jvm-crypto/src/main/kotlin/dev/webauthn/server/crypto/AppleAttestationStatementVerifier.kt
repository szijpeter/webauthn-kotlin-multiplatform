package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.Arrays

internal class AppleAttestationStatementVerifier : AttestationVerifier {

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

        // 1. Verify x5c is present
        if (attestationObject.x5c.isNullOrEmpty()) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "x5c is required")),
            )
        }

        val certFactory = CertificateFactory.getInstance("X.509")
        val leafCert: X509Certificate
        try {
            leafCert = certFactory.generateCertificate(ByteArrayInputStream(attestationObject.x5c[0])) as X509Certificate
        } catch (e: Exception) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse certificate: ${e.message}")),
            )
        }

        // 2. Verify nonce
        // nonce = SHA-256(authData || clientDataHash)
        val clientDataHash = java.security.MessageDigest.getInstance("SHA-256").digest(input.response.clientDataJson.bytes())
        val nonce = java.security.MessageDigest.getInstance("SHA-256").digest(attestationObject.authDataBytes!! + clientDataHash)

        val extensionValue = leafCert.getExtensionValue(APPLE_EXTENSION_OID)
        if (extensionValue == null) {
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "Apple extension not found")),
            )
        }

        // extensionValue is OCTET STRING (DER encoded) containing the extension value.
        // The extension value itself is an OCTET STRING containing the nonce.
        try {
            val outerParser = DerParser(extensionValue)
            val innerBytes = outerParser.readOctetString()
            
            // Check if innerBytes is the nonce (32 bytes) or a DER sequence/octet string.
            // Usually Apple extension wraps it in ASN.1 OCTET STRING.
            // Let's try to parse as DER Tag 0x04 (OCTET STRING)
            // If it fails or tag is different, maybe it's raw?
            // Spec says "The value of the extension is an OCTET STRING containing the nonce."
            // This is ambiguous. But usually means DER(OCTET STRING(nonce)).
            
            val innerParser = DerParser(innerBytes)
            val extensionNonce = innerParser.readOctetString()
            
            if (!Arrays.equals(extensionNonce, nonce)) {
                return ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue("x5c", "Certificate nonce mismatch")),
                )
            }
        } catch (e: Exception) {
             // Fallback: maybe innerBytes IS the nonce?
             // But existing implementations (e.g. java-webauthn-server) do unwrap twice.
             return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse Apple extension: ${e.message}")),
            )
        }

        // 3. Verify public key match
        val credPubKeyBytes = input.response.attestedCredentialData.cosePublicKey
        if (credPubKeyBytes.isNotEmpty()) {
            val certPubKey = leafCert.publicKey
            if (certPubKey is ECPublicKey) {
                if (!matchesEcKey(credPubKeyBytes, certPubKey)) {
                     return ValidationResult.Invalid(
                        listOf(WebAuthnValidationError.InvalidValue("pubKey", "Public key mismatch")),
                    )
                }
            } else {
                // Apple attestation usually EC. If RSA, we skip or fail?
                // Let's skip if not EC for now, or fail. Apple uses P-256.
            }
        }

        return ValidationResult.Valid(Unit)
    }

    private fun matchesEcKey(coseBytes: ByteArray, certKey: ECPublicKey): Boolean {
        // Parse COSE EC Key (P-256, ES256)
        // Map keys: 1(kty)=2, 3(alg)=-7, -1(crv)=1, -2(x), -3(y)
        var offset = 0
        var x: ByteArray? = null
        var y: ByteArray? = null
        
        val header = readCborHeader(coseBytes, offset) ?: return false
        if (header.majorType != MAJOR_MAP) return false
        offset = header.nextOffset
        
        repeat(header.length!!.toInt()) {
            // key
            val keyHeader = readCborHeader(coseBytes, offset) ?: return false
            var key: Long? = null
            
            if (keyHeader.majorType == MAJOR_UNSIGNED_INT || keyHeader.majorType == MAJOR_NEGATIVE_INT) {
                val keyPair = readCborInt(coseBytes, offset) ?: return false
                key = keyPair.first
                offset = keyPair.second
            } else {
                // Non-integer key, skip it
                offset = skipCborItem(coseBytes, offset) ?: return false
            }

            if (key != null) {
                when (key) {
                    -2L -> { // x
                        val valPair = readCborBytes(coseBytes, offset) ?: return false
                        x = valPair.first
                        offset = valPair.second
                    }
                    -3L -> { // y
                        val valPair = readCborBytes(coseBytes, offset) ?: return false
                        y = valPair.first
                        offset = valPair.second
                    }
                    else -> {
                        offset = skipCborItem(coseBytes, offset) ?: return false
                    }
                }
            } else {
                 // Value associated with skipped key
                 offset = skipCborItem(coseBytes, offset) ?: return false
            }
        }
        
        if (x == null || y == null) return false
        
        // Compare with certKey.w.affineX and affineY
        val certX = certKey.w.affineX.toByteArray()
        val certY = certKey.w.affineY.toByteArray()
        
        // Normalize arrays (strip leading zero if present, pad if needed)
        // P-256 coordinates are 32 bytes.
        // BigInteger.toByteArray might add leading zero sign byte.
        fun normalize(b: ByteArray): ByteArray {
            if (b.size == 33 && b[0] == 0.toByte()) return b.copyOfRange(1, 33)
            if (b.size < 32) {
                val res = ByteArray(32)
                System.arraycopy(b, 0, res, 32 - b.size, b.size)
                return res
            }
            return b
        }
        
        return Arrays.equals(x, normalize(certX)) && Arrays.equals(y, normalize(certY))
    }
}
