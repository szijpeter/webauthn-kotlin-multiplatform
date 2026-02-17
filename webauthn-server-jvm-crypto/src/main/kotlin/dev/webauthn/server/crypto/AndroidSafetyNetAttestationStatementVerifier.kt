package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.util.Base64

internal class AndroidSafetyNetAttestationStatementVerifier(
    private val trustAnchorSource: TrustAnchorSource? = null,
    private val digestService: DigestService = JvmDigestService(),
    private val certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    private val certificateInspector: CertificateInspector = JvmCertificateInspector(),
    private val certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
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

        val x5cPattern = "\"x5c\"\\s*:\\s*\\[([^\\]]+)\\]".toRegex()
        val x5cMatch = x5cPattern.find(headerJson)
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "x5c missing in JWS header")),
            )

        val certsB64 = x5cMatch.groupValues[1].split(",").map { it.trim().trim('"') }.filter { it.isNotEmpty() }
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

        if (trustAnchorSource != null) {
            val chainVerifier = TrustChainVerifier(trustAnchorSource, certificateChainValidator)
            val chainResult = chainVerifier.verify(certsDer, null)
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
        val noncePattern = "\"nonce\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        val nonceMatch = noncePattern.find(payloadJson)
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
            Base64.getDecoder().decode(nonceMatch.groupValues[1])
        } catch (_: IllegalArgumentException) {
            Base64.getUrlDecoder().decode(nonceMatch.groupValues[1])
        }
        if (!jwsNonceBytes.contentEquals(expectedNonce)) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("nonce", "Nonce mismatch")),
            )
        }

        if (!payloadJson.contains("\"ctsProfileMatch\":true") && !payloadJson.contains("\"ctsProfileMatch\": true")) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("ctsProfileMatch", "Device not compatible (ctsProfileMatch false)")),
            )
        }

        return ValidationResult.Valid(Unit)
    }
}
