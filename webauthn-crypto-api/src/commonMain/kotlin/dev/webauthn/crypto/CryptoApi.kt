package dev.webauthn.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ValidationResult

/**
 * Verifies signatures using an authenticator credential public key.
 *
 * Migration note:
 * This interface remains the credential/self-attestation verifier.
 * For x5c certificate-based signature verification in attestation statement verifiers, prefer [CertificateSignatureVerifier].
 */
public fun interface SignatureVerifier {
    public fun verify(
        algorithm: CoseAlgorithm,
        publicKeyCose: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean
}

/**
 * Parses COSE public keys into a platform-specific verification representation.
 * Returns [CoseParseResult]; unsupported or malformed keys fail deterministically (no raw-byte fallback).
 *
 * Migration note:
 * New call sites should prefer [CosePublicKeyDecoder] and [CosePublicKeyNormalizer] to keep attestation verifiers platform-neutral.
 */
public fun interface CoseKeyParser {
    public fun parsePublicKey(coseKey: ByteArray): CoseParseResult
}

/**
 * Result of parsing a COSE public key. Success carries [ParsedCosePublicKey]; failure carries a [CoseParseFailure] reason.
 */
public sealed interface CoseParseResult {
    public data class Success(public val parsed: ParsedCosePublicKey) : CoseParseResult
    public data class Failure(public val reason: CoseParseFailure) : CoseParseResult
}

/**
 * Structured reason for COSE parse failure. Unsupported key shapes and malformed input fail deterministically.
 */
public sealed interface CoseParseFailure {
    public data class MalformedCbor(public val message: String) : CoseParseFailure
    public data class UnsupportedKeyType(public val kty: Long) : CoseParseFailure
    public data class UnsupportedCurve(public val crv: Long) : CoseParseFailure
    public data class MissingRequiredParameter(public val label: String) : CoseParseFailure
    public data class UnsupportedAlgorithm(public val alg: Long) : CoseParseFailure
}

public fun interface AttestationVerifier {
    public fun verify(input: RegistrationValidationInput): ValidationResult<Unit>
}

public fun interface TrustAnchorSource {
    public fun findTrustAnchors(aaguid: ByteArray?): List<ByteArray>
}

public fun interface RpIdHasher {
    public fun hashRpId(rpId: String): ByteArray
}

public enum class CoseAlgorithm(public val code: Int) {
    ES256(-7),
    RS256(-257),
    EdDSA(-8),
}

/**
 * Shared COSE algorithm mapper. Use this instead of duplicating
 * [CoseAlgorithm].entries.find { it.code == code } in verifiers and adapters.
 */
public fun coseAlgorithmFromCode(code: Int): CoseAlgorithm? =
    CoseAlgorithm.entries.find { it.code == code }

public data class ParsedCosePublicKey(
    public val algorithm: CoseAlgorithm,
    public val x509SubjectPublicKeyInfo: ByteArray,
)

public data class SignedAuthenticationPayload(
    public val authenticatorData: AuthenticatorData,
    public val clientDataHash: ByteArray,
    public val signature: Base64UrlBytes,
)
