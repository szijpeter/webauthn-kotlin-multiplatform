package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ImmutableBytes
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult

public class JvmRpIdHasher : RpIdHasher {
    override fun hashRpId(rpId: String): RpIdHash =
        RpIdHash.fromBytes(SignumPrimitives.sha256(rpId.toByteArray(Charsets.UTF_8)))
}

public class JvmSignatureVerifier : SignatureVerifier {
    override fun verify(
        algorithm: dev.webauthn.crypto.CoseAlgorithm,
        publicKeyCose: ImmutableBytes,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean = SignumPrimitives.verifyWithCosePublicKey(algorithm, publicKeyCose, data, signature)

    public fun verify(
        algorithm: dev.webauthn.crypto.CoseAlgorithm,
        publicKeyCose: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean = verify(algorithm, ImmutableBytes.fromBytes(publicKeyCose), data, signature)
}

public class StrictAttestationVerifier(
    signatureVerifier: SignatureVerifier? = null,
    trustAnchorSource: TrustAnchorSource? = ResourceTrustAnchorSource(),
) : AttestationVerifier {

    private val delegate = CompositeAttestationVerifier(
        signatureVerifier = signatureVerifier,
        trustAnchorSource = trustAnchorSource,
    )

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        return delegate.verify(input)
    }
}
