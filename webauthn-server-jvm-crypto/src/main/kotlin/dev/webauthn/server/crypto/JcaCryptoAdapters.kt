package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.SignatureVerifier
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * JCA-backed implementation of [DigestService].
 * Uses the default JCA provider (e.g. JDK) for SHA-256.
 */
public class JcaDigestService : DigestService {
    override fun sha256(input: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(input)
    }
}

/**
 * JCA-backed implementation of [SignatureVerifier].
 * Uses the default JCA provider (e.g. JDK) for key decoding and signature verification.
 */
public class JcaSignatureVerifier(
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
