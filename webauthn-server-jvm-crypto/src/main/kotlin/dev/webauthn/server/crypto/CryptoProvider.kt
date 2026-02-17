package dev.webauthn.server.crypto

import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.SignatureVerifier

/**
 * Selects the underlying crypto implementation for signature verification and digest operations.
 *
 * - [JCA]: Default JDK/JCA provider (legacy path). Use for phased rollout default.
 * - [SIGNUM]: Signum-based provider when available. Enable explicitly for phased rollout.
 */
public enum class CryptoProvider {
    /** Default JCA (JDK) provider. */
    JCA,

    /** Signum KMP crypto provider (JVM: JCA-compatible). */
    SIGNUM,
}

/**
 * Creates a [SignatureVerifier] for the given [CryptoProvider].
 */
public fun CryptoProvider.createSignatureVerifier(
    cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
): SignatureVerifier = when (this) {
    CryptoProvider.JCA -> JcaSignatureVerifier(cosePublicKeyDecoder, cosePublicKeyNormalizer)
    CryptoProvider.SIGNUM -> SignumSignatureVerifier(cosePublicKeyDecoder, cosePublicKeyNormalizer)
}

/**
 * Creates a [DigestService] for the given [CryptoProvider].
 */
public fun CryptoProvider.createDigestService(): DigestService = when (this) {
    CryptoProvider.JCA -> JcaDigestService()
    CryptoProvider.SIGNUM -> SignumDigestService()
}
