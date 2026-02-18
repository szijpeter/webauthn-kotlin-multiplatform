package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.DigestService
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.util.Base64

internal class AndroidSafetyNetAttestationStatementVerifier(
    private val trustChainVerifier: TrustChainVerifier? = null,
    private val digestService: DigestService = JvmDigestService(),
    private val certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    private val certificateInspector: CertificateInspector = JvmCertificateInspector(),
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

        if (attestationObject.response == null) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "response is required")),
            )
        }

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
        val headerJson = String(Base64.getUrlDecoder().decode(headerB64), Charsets.UTF_8)

        val certsB64 = extractJsonStringArray(headerJson, "x5c")
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "x5c missing in JWS header")),
            )

        if (certsB64.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "No certificates in JWS header")),
            )
        }

        val certsDer = try {
            certsB64.map { Base64.getDecoder().decode(it) }
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to decode certificate: ${e.message}")),
            )
        }
        val leafCertDer = certsDer.first()

        try {
            certificateInspector.inspect(leafCertDer)
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse certificate: ${e.message}")),
            )
        }

        if (trustChainVerifier != null) {
            val chainResult = trustChainVerifier.verify(certsDer, null)
            if (chainResult is ValidationResult.Invalid) {
                return chainResult
            }
        }

        val sigBytes = try {
            Base64.getUrlDecoder().decode(signatureB64)
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "Invalid JWS signature encoding: ${e.message}")),
            )
        }
        val signedData = "$headerB64.$payloadB64".toByteArray(Charsets.UTF_8)
        if (!certificateSignatureVerifier.verify(CoseAlgorithm.RS256, leafCertDer, signedData, sigBytes)) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "JWS signature verification failed")),
            )
        }

        val payloadJson = String(Base64.getUrlDecoder().decode(payloadB64), Charsets.UTF_8)
        val nonceValue = extractJsonString(payloadJson, "nonce")
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("nonce", "Nonce missing in payload")),
            )

        val authData = attestationObject.authDataBytes
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("authData", "authData is required")),
            )
        val clientDataHash = digestService.sha256(input.response.clientDataJson.bytes())
        val expectedNonce = digestService.sha256(authData + clientDataHash)

        val jwsNonceBytes = try {
            Base64.getDecoder().decode(nonceValue)
        } catch (_: IllegalArgumentException) {
            Base64.getUrlDecoder().decode(nonceValue)
        }
        if (!jwsNonceBytes.contentEquals(expectedNonce)) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("nonce", "Nonce mismatch")),
            )
        }

        val ctsMatch = extractJsonBoolean(payloadJson, "ctsProfileMatch")
        if (ctsMatch != true) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("ctsProfileMatch", "Device not compatible (ctsProfileMatch false)")),
            )
        }

        return ValidationResult.Valid(Unit)
    }

    // ---- Deterministic JSON helpers (no regex) ----

    /**
     * Extracts a JSON string array value for the given [key].
     * Searches for `"key":[` and parses quoted string elements until `]`.
     */
    private fun extractJsonStringArray(json: String, key: String): List<String>? {
        val searchKey = "\"$key\""
        var idx = json.indexOf(searchKey)
        if (idx == -1) return null
        idx += searchKey.length
        idx = skipWhitespace(json, idx)
        if (idx >= json.length || json[idx] != ':') return null
        idx = skipWhitespace(json, idx + 1)
        if (idx >= json.length || json[idx] != '[') return null
        idx++ // skip '['
        val result = mutableListOf<String>()
        while (idx < json.length) {
            idx = skipWhitespace(json, idx)
            if (idx >= json.length) return null
            if (json[idx] == ']') return result
            if (json[idx] == ',') {
                idx++
                continue
            }
            if (json[idx] == '"') {
                val strResult = readJsonString(json, idx) ?: return null
                result.add(strResult.first)
                idx = strResult.second
            } else {
                return null // unexpected token
            }
        }
        return null // unterminated array
    }

    /**
     * Extracts a JSON string value for the given [key].
     * Searches for `"key":"value"`.
     */
    private fun extractJsonString(json: String, key: String): String? {
        val searchKey = "\"$key\""
        var idx = json.indexOf(searchKey)
        if (idx == -1) return null
        idx += searchKey.length
        idx = skipWhitespace(json, idx)
        if (idx >= json.length || json[idx] != ':') return null
        idx = skipWhitespace(json, idx + 1)
        if (idx >= json.length || json[idx] != '"') return null
        val strResult = readJsonString(json, idx) ?: return null
        return strResult.first
    }

    /**
     * Extracts a JSON boolean value for the given [key].
     */
    private fun extractJsonBoolean(json: String, key: String): Boolean? {
        val searchKey = "\"$key\""
        var idx = json.indexOf(searchKey)
        if (idx == -1) return null
        idx += searchKey.length
        idx = skipWhitespace(json, idx)
        if (idx >= json.length || json[idx] != ':') return null
        idx = skipWhitespace(json, idx + 1)
        return when {
            json.startsWith("true", idx) -> true
            json.startsWith("false", idx) -> false
            else -> null
        }
    }

    /**
     * Reads a JSON string starting at the opening quote at [start].
     * Returns (string value, index after closing quote) or null on error.
     */
    private fun readJsonString(json: String, start: Int): Pair<String, Int>? {
        if (start >= json.length || json[start] != '"') return null
        val sb = StringBuilder()
        var i = start + 1
        while (i < json.length) {
            val c = json[i]
            if (c == '\\') {
                i++
                if (i >= json.length) return null
                sb.append(json[i])
            } else if (c == '"') {
                return sb.toString() to (i + 1)
            } else {
                sb.append(c)
            }
            i++
        }
        return null // unterminated string
    }

    private fun skipWhitespace(json: String, start: Int): Int {
        var i = start
        while (i < json.length && json[i].isWhitespace()) i++
        return i
    }
}
