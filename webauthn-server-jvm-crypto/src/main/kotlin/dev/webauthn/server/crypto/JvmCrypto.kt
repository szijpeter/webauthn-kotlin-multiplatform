package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CoseKeyParser
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.ParsedCosePublicKey
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

public class JvmRpIdHasher(
    private val digestService: DigestService = JvmDigestService(),
) : RpIdHasher {
    override fun hashRpId(rpId: String): ByteArray {
        return digestService.sha256(rpId.toByteArray(Charsets.UTF_8))
    }
}

public class JvmSignatureVerifier(
    private val cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    private val cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
) : SignatureVerifier {
    override fun verify(
        algorithm: CoseAlgorithm,
        publicKeyCose: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val material = cosePublicKeyDecoder.decode(publicKeyCose)
        val parsedAlgorithm = material?.alg?.toInt()?.let { code ->
            CoseAlgorithm.entries.find { it.code == code }
        } ?: algorithm
        val spki = material?.let { cosePublicKeyNormalizer.toSubjectPublicKeyInfo(it) } ?: publicKeyCose

        val keyFactory = when (parsedAlgorithm) {
            CoseAlgorithm.ES256 -> KeyFactory.getInstance("EC")
            CoseAlgorithm.RS256 -> KeyFactory.getInstance("RSA")
            CoseAlgorithm.EdDSA -> KeyFactory.getInstance("Ed25519")
        }

        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(spki))

        val signatureInstance = when (parsedAlgorithm) {
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
    private val cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    private val cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
) : CoseKeyParser {
    override fun parsePublicKey(coseKey: ByteArray): ParsedCosePublicKey {
        val material = cosePublicKeyDecoder.decode(coseKey)
        val spki = material?.let(cosePublicKeyNormalizer::toSubjectPublicKeyInfo) ?: coseKey
        val algorithm = material?.alg?.toInt()?.let { code ->
            CoseAlgorithm.entries.find { it.code == code }
        } ?: defaultAlgorithm
        return ParsedCosePublicKey(
            algorithm = algorithm,
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
