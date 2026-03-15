package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult

/** JVM RP ID hasher backed by Signum SHA-256 primitives. */
public class JvmRpIdHasher : RpIdHasher {
    override fun hashRpId(rpId: String): RpIdHash =
        RpIdHash.fromBytes(SignumPrimitives.sha256(rpId.toByteArray(Charsets.UTF_8)))
}

/** JVM signature verifier backed by Signum COSE verification primitives. */
public class JvmSignatureVerifier : SignatureVerifier {
    override fun verify(
        algorithm: dev.webauthn.crypto.CoseAlgorithm,
        publicKeyCose: CosePublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean = SignumPrimitives.verifyWithCosePublicKey(algorithm, publicKeyCose, data, signature)
}

/** Strict server attestation verifier wiring JVM defaults for production use. */
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
