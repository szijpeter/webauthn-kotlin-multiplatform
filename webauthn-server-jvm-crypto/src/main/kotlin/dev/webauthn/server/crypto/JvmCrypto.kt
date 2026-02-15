package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CoseKeyParser
import dev.webauthn.crypto.ParsedCosePublicKey
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

public class JvmRpIdHasher : RpIdHasher {
    override fun hashRpId(rpId: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
    }
}

public class JvmSignatureVerifier : SignatureVerifier {
    override fun verify(
        algorithm: CoseAlgorithm,
        publicKeyCose: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val parsed = JvmCoseKeyParser(algorithm).parsePublicKey(publicKeyCose)
        val keyFactory = when (parsed.algorithm) {
            CoseAlgorithm.ES256 -> KeyFactory.getInstance("EC")
            CoseAlgorithm.RS256 -> KeyFactory.getInstance("RSA")
            CoseAlgorithm.EdDSA -> KeyFactory.getInstance("Ed25519")
        }

        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(parsed.x509SubjectPublicKeyInfo))

        val signatureInstance = when (parsed.algorithm) {
            CoseAlgorithm.ES256 -> Signature.getInstance("SHA256withECDSA")
            CoseAlgorithm.RS256 -> Signature.getInstance("SHA256withRSA")
            CoseAlgorithm.EdDSA -> Signature.getInstance("Ed25519")
        }

        signatureInstance.initVerify(publicKey)
        signatureInstance.update(data)
        return signatureInstance.verify(signature)
    }
}

public class JvmCoseKeyParser(
    private val defaultAlgorithm: CoseAlgorithm = CoseAlgorithm.ES256,
) : CoseKeyParser {
    override fun parsePublicKey(coseKey: ByteArray): ParsedCosePublicKey {
        val spki = CoseToSpkiConverter.convert(coseKey) ?: coseKey
        return ParsedCosePublicKey(
            algorithm = defaultAlgorithm,
            x509SubjectPublicKeyInfo = spki,
        )
    }
}

public class StrictAttestationVerifier(
    signatureVerifier: SignatureVerifier? = null,
    trustAnchorSource: TrustAnchorSource? = ResourceTrustAnchorSource(),
) : AttestationVerifier {
    private val delegate = CompositeAttestationVerifier(signatureVerifier, trustAnchorSource)

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        return delegate.verify(input)
    }
}
