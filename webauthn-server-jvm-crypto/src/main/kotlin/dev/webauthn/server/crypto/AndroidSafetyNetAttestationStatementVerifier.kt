package dev.webauthn.server.crypto

import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.sign.verifierFor
import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal data class SafetyNetJwsPayload(
    val nonce: String,
    val ctsProfileMatch: Boolean? = null,
)

internal class AndroidSafetyNetAttestationStatementVerifier(
    private val trustChainVerifier: TrustChainVerifier? = null,
    private val certificateInspector: JvmCertificateInspector = JvmCertificateInspector(),
) : AttestationVerifier {

    private val json = Json {
        ignoreUnknownKeys = true
    }

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

        val responseBytes = attestationObject.response
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("attStmt", "response is required")),
            )

        val parsedJws = JwsSigned.deserialize(responseBytes.decodeToString()).getOrNull()
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "Invalid JWS format")),
            )

        val certificateChain = parsedJws.header.certificateChain
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "x5c missing in JWS header")),
            )

        if (certificateChain.isEmpty()) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("x5c", "No certificates in JWS header")),
            )
        }

        val certsDer = certificateChain.map { it.encodeToDer() }
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

        val algorithm = parsedJws.header.algorithm
        if (algorithm !is JwsAlgorithm.Signature.RSA || algorithm != JwsAlgorithm.Signature.RS256) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "Unsupported JWS algorithm: ${algorithm.identifier}")),
            )
        }

        val publicKey = parsedJws.header.publicKey
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "No public key found in JWS header")),
            )

        val verifier = algorithm.verifierFor(publicKey).getOrNull()
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "JWS verifier initialization failed")),
            )

        if (verifier.verify(parsedJws.plainSignatureInput, parsedJws.signature).isFailure) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "JWS signature verification failed")),
            )
        }

        val payload = try {
            val payloadObject = json.parseToJsonElement(parsedJws.payload.decodeToString()).jsonObject
            SafetyNetJwsPayload(
                nonce = payloadObject["nonce"]?.jsonPrimitive?.contentOrNull
                    ?: throw IllegalArgumentException("nonce missing from JWS payload"),
                ctsProfileMatch = payloadObject["ctsProfileMatch"]?.jsonPrimitive?.booleanOrNull,
            )
        } catch (e: Exception) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("response", "Failed to parse JWS payload: ${e.message}")),
            )
        }

        val authData = attestationObject.authDataBytes
            ?: return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.MissingValue("authData", "authData is required")),
            )
        val clientDataHash = SignumPrimitives.sha256(input.response.clientDataJson.bytes())
        val expectedNonce = SignumPrimitives.sha256(authData + clientDataHash)

        val jwsNonceBytes = try {
            Base64.getDecoder().decode(payload.nonce)
        } catch (_: IllegalArgumentException) {
            Base64.getUrlDecoder().decode(payload.nonce)
        }
        if (!jwsNonceBytes.contentEquals(expectedNonce)) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("nonce", "Nonce mismatch")),
            )
        }

        if (payload.ctsProfileMatch != true) {
            return ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("ctsProfileMatch", "Device not compatible (ctsProfileMatch false)")),
            )
        }

        return ValidationResult.Valid(Unit)
    }
}
