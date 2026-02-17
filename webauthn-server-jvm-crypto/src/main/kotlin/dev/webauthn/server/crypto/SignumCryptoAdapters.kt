package dev.webauthn.server.crypto

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.SignatureVerifier
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Security
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Provider name for Signum when registered as a JCA provider.
 * If Signum is not registered, [SignumDigestService] and [SignumSignatureVerifier]
 * fall back to the default JCA provider so the module remains usable.
 */
public const val SIGNUM_PROVIDER_NAME: String = "Signum"

private fun signumProviderOrNull(): String? =
    if (Security.getProvider(SIGNUM_PROVIDER_NAME) != null) SIGNUM_PROVIDER_NAME else null

/**
 * Signum-backed implementation of [DigestService].
 * Uses the Signum JCA provider for SHA-256 when registered; otherwise falls back to default JCA.
 */
public class SignumDigestService : DigestService {
    override fun sha256(input: ByteArray): ByteArray {
        val provider = signumProviderOrNull()
        return if (provider != null) {
            MessageDigest.getInstance("SHA-256", provider).digest(input)
        } else {
            MessageDigest.getInstance("SHA-256").digest(input)
        }
    }
}

/**
 * Signum-backed implementation of [SignatureVerifier].
 * Uses the Signum JCA provider for key decoding and signature verification when registered;
 * otherwise falls back to default JCA.
 */
public class SignumSignatureVerifier(
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

        val provider = signumProviderOrNull()

        val keyFactory = when (parsedAlgorithm) {
            CoseAlgorithm.ES256 -> if (provider != null) KeyFactory.getInstance("EC", provider) else KeyFactory.getInstance("EC")
            CoseAlgorithm.RS256 -> if (provider != null) KeyFactory.getInstance("RSA", provider) else KeyFactory.getInstance("RSA")
            CoseAlgorithm.EdDSA -> if (provider != null) KeyFactory.getInstance("Ed25519", provider) else KeyFactory.getInstance("Ed25519")
        }

        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(spki))

        val signatureInstance = when (parsedAlgorithm) {
            CoseAlgorithm.ES256 -> if (provider != null) Signature.getInstance("SHA256withECDSA", provider) else Signature.getInstance("SHA256withECDSA")
            CoseAlgorithm.RS256 -> if (provider != null) Signature.getInstance("SHA256withRSA", provider) else Signature.getInstance("SHA256withRSA")
            CoseAlgorithm.EdDSA -> if (provider != null) Signature.getInstance("Ed25519", provider) else Signature.getInstance("Ed25519")
        }

        signatureInstance.initVerify(publicKey)
        signatureInstance.update(data)
        return signatureInstance.verify(signature)
    }
}
