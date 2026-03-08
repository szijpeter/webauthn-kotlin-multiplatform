package dev.webauthn.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ImmutableBytes
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult

public fun interface SignatureVerifier {
    public fun verify(
        algorithm: CoseAlgorithm,
        publicKeyCose: ImmutableBytes,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean
}

public fun interface AttestationVerifier {
    public fun verify(input: RegistrationValidationInput): ValidationResult<Unit>
}

public fun interface TrustAnchorSource {
    public fun findTrustAnchors(aaguid: Aaguid?): List<ImmutableBytes>
}

public fun interface RpIdHasher {
    public fun hashRpId(rpId: String): RpIdHash
}

public enum class CoseAlgorithm(public val code: Int) {
    ES256(-7),
    RS256(-257),
    EdDSA(-8),
}

public fun coseAlgorithmFromCode(code: Int): CoseAlgorithm? =
    CoseAlgorithm.entries.find { it.code == code }

public data class SignedAuthenticationPayload(
    public val authenticatorData: AuthenticatorData,
    public val clientDataHash: ImmutableBytes,
    public val signature: Base64UrlBytes,
)
