package dev.webauthn.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ClientDataHash
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult

/** Signature verification abstraction for COSE credential public keys. */
public fun interface SignatureVerifier {
    public fun verify(
        algorithm: CoseAlgorithm,
        publicKeyCose: CosePublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean
}

/** Attestation statement verification abstraction used by server validators. */
public fun interface AttestationVerifier {
    public fun verify(input: RegistrationValidationInput): ValidationResult<Unit>
}

/** Source of trust anchors optionally keyed by authenticator AAGUID. */
public fun interface TrustAnchorSource {
    public fun findTrustAnchors(aaguid: Aaguid?): List<Base64UrlBytes>
}

/** Hashing abstraction for RP ID normalization/verification. */
public fun interface RpIdHasher {
    public fun hashRpId(rpId: String): RpIdHash
}

/** COSE algorithm codes used in WebAuthn signatures and attestation verification. */
@Suppress("MagicNumber")
public enum class CoseAlgorithm(public val code: Int) {
    ES256(-7),
    RS256(-257),
    EdDSA(-8),
}

public fun coseAlgorithmFromCode(code: Int): CoseAlgorithm? =
    CoseAlgorithm.entries.find { it.code == code }

/** Signed assertion payload components consumed by signature verifiers. */
public data class SignedAuthenticationPayload(
    public val authenticatorData: AuthenticatorData,
    public val clientDataHash: ClientDataHash,
    public val signature: Base64UrlBytes,
)
