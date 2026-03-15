@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client.prf

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.authTag
import at.asitplus.signum.indispensable.symmetric.keyFrom
import at.asitplus.signum.indispensable.symmetric.nonce
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.kdf.deriveKey
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PublicKeyCredentialRequestOptions

@ExperimentalWebAuthnL3Api
/** Selects which PRF result value should be used for key derivation. */
public enum class PrfOutputSelection {
    FIRST,
    SECOND,
}

/** Thrown when a requested PRF output value is missing from the authenticator response. */
public class MissingPrfOutputException(
    message: String,
) : IllegalArgumentException(message)

/** Serialized AES-GCM payload emitted by PRF-derived encryption helpers. */
public data class PrfCiphertext(
    public val nonce: Base64UrlBytes,
    public val ciphertext: Base64UrlBytes,
    public val authTag: Base64UrlBytes,
    public val associatedData: Base64UrlBytes? = null,
)

@ExperimentalWebAuthnL3Api
/** Low-level helpers for PRF extension request wiring and symmetric crypto operations. */
public object PrfCrypto {
    public const val DEFAULT_CONTEXT: String = "webauthn-prf-crypto"

    private const val AES_KEY_LENGTH_BYTES: Int = 32
    private const val HKDF_SALT_LENGTH_BYTES: Int = 32
    private const val KEY_HASH_PREFIX_BYTES: Int = 8
    private val aesGcm = SymmetricEncryptionAlgorithm.AES_256.GCM
    private const val BYTE_MASK: Int = 0xFF
    private const val NIBBLE_SHIFT: Int = 4
    private const val NIBBLE_MASK: Int = 0x0F
    private const val HEX_CHARS: String = "0123456789abcdef"

    public fun withPrfEvaluation(
        options: PublicKeyCredentialRequestOptions,
        firstSalt: Base64UrlBytes,
        secondSalt: Base64UrlBytes? = null,
    ): PublicKeyCredentialRequestOptions {
        return withPrfEvaluation(
            options = options,
            evaluation = AuthenticationExtensionsPRFValues(first = firstSalt, second = secondSalt),
        )
    }

    public fun withPrfEvaluation(
        options: PublicKeyCredentialRequestOptions,
        evaluation: AuthenticationExtensionsPRFValues,
    ): PublicKeyCredentialRequestOptions {
        val existingExtensions = options.extensions ?: AuthenticationExtensionsClientInputs()
        val updatedPrf = (existingExtensions.prf ?: PrfExtensionInput()).copy(
            eval = evaluation,
            evalByCredential = null,
        )
        return options.copy(
            extensions = existingExtensions.copy(prf = updatedPrf),
        )
    }

    public fun prfResultsOrNull(response: AuthenticationResponse): AuthenticationExtensionsPRFValues? {
        return response.extensions?.prf?.results
    }

    public fun requirePrfResults(response: AuthenticationResponse): AuthenticationExtensionsPRFValues {
        return requireNotNull(prfResultsOrNull(response)) {
            "PRF extension was requested but no PRF results were returned by the authenticator."
        }
    }

    public suspend fun deriveAes256Key(
        prfOutput: Base64UrlBytes,
        context: String = DEFAULT_CONTEXT,
        hkdfSalt: Base64UrlBytes? = null,
    ): Base64UrlBytes {
        val derived = deriveAes256KeyBytes(
            prfOutput = prfOutput.bytes(),
            context = context,
            hkdfSalt = hkdfSalt?.bytes(),
        )
        return Base64UrlBytes.fromBytes(derived)
    }

    internal suspend fun deriveAes256KeyBytes(
        prfOutput: ByteArray,
        context: String = DEFAULT_CONTEXT,
        hkdfSalt: ByteArray? = null,
    ): ByteArray {
        require(context.isNotBlank()) { "context must not be blank" }
        if (hkdfSalt != null) {
            require(hkdfSalt.size == HKDF_SALT_LENGTH_BYTES) {
                "hkdfSalt must be exactly $HKDF_SALT_LENGTH_BYTES bytes."
            }
        }
        val derived = HKDF.SHA256(context.encodeToByteArray())
            .deriveKey(
                salt = hkdfSalt ?: ByteArray(HKDF_SALT_LENGTH_BYTES),
                ikm = prfOutput,
                derivedKeyLength = 256.bit,
            )
            .getOrThrow()
        require(derived.size == AES_KEY_LENGTH_BYTES) {
            "Expected a $AES_KEY_LENGTH_BYTES-byte derived key, got ${derived.size}."
        }
        return derived
    }

    public suspend fun createSession(
        prfResults: AuthenticationExtensionsPRFValues,
        outputSelection: PrfOutputSelection = PrfOutputSelection.FIRST,
        context: String = DEFAULT_CONTEXT,
        hkdfSalt: Base64UrlBytes? = null,
    ): PrfCryptoSession {
        val selectedOutput = selectOutput(prfResults, outputSelection)
        val keyBytes = deriveAes256KeyBytes(
            prfOutput = selectedOutput.bytes(),
            context = context,
            hkdfSalt = hkdfSalt?.bytes(),
        )
        return PrfCryptoSession(
            keyBytes = keyBytes,
            keyFingerprint = keyFingerprint(keyBytes),
            context = context,
        )
    }

    public suspend fun encryptAesGcm(
        key: Base64UrlBytes,
        plaintext: Base64UrlBytes,
        associatedData: Base64UrlBytes? = null,
    ): PrfCiphertext {
        return encryptAesGcmWithRawKey(
            keyBytes = key.bytes(),
            plaintext = plaintext.bytes(),
            associatedData = associatedData?.bytes(),
        )
    }

    internal suspend fun encryptAesGcmWithRawKey(
        keyBytes: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray? = null,
    ): PrfCiphertext {
        val symmetricKey = aesGcm.keyFrom(keyBytes).getOrThrow()
        val sealedBox = symmetricKey
            .encrypt(
                data = plaintext,
                authenticatedData = associatedData,
            )
            .getOrThrow()
        return PrfCiphertext(
            nonce = Base64UrlBytes.fromBytes(sealedBox.nonce),
            ciphertext = Base64UrlBytes.fromBytes(sealedBox.encryptedData),
            authTag = Base64UrlBytes.fromBytes(sealedBox.authTag),
            associatedData = associatedData?.let(Base64UrlBytes::fromBytes),
        )
    }

    public suspend fun decryptAesGcm(
        key: Base64UrlBytes,
        ciphertext: PrfCiphertext,
    ): Base64UrlBytes {
        val plaintext = decryptAesGcmWithRawKey(
            keyBytes = key.bytes(),
            ciphertext = ciphertext,
        )
        return Base64UrlBytes.fromBytes(plaintext)
    }

    internal suspend fun decryptAesGcmWithRawKey(
        keyBytes: ByteArray,
        ciphertext: PrfCiphertext,
    ): ByteArray {
        val symmetricKey = aesGcm.keyFrom(keyBytes).getOrThrow()
        val plaintext = symmetricKey
            .decrypt(
                nonce = ciphertext.nonce.bytes(),
                encryptedData = ciphertext.ciphertext.bytes(),
                authTag = ciphertext.authTag.bytes(),
                authenticatedData = ciphertext.associatedData?.bytes() ?: ByteArray(0),
            )
            .getOrThrow()
        return plaintext
    }

    internal fun keyFingerprint(keyBytes: ByteArray): String {
        val hash = Digest.SHA256.digest(keyBytes)
        val limit = minOf(KEY_HASH_PREFIX_BYTES, hash.size)
        return buildString(limit * 2) {
            for (index in 0 until limit) {
                val value = hash[index].toInt() and BYTE_MASK
                append(HEX_CHARS[value ushr NIBBLE_SHIFT])
                append(HEX_CHARS[value and NIBBLE_MASK])
            }
        }
    }

    internal fun selectOutput(
        values: AuthenticationExtensionsPRFValues,
        selection: PrfOutputSelection,
    ): Base64UrlBytes {
        return when (selection) {
            PrfOutputSelection.FIRST -> values.first
            PrfOutputSelection.SECOND -> values.second
                ?: throw MissingPrfOutputException(
                    "PRF output selection is SECOND but authenticator returned only one output.",
                )
        }
    }
}

/** In-memory, zeroizable session that encapsulates a PRF-derived AES key. */
public class PrfCryptoSession internal constructor(
    keyBytes: ByteArray,
    public val keyFingerprint: String,
    public val context: String,
) {
    private val aesKeyBytes: ByteArray = keyBytes.copyOf()
    private var cleared: Boolean = false

    public val isCleared: Boolean
        get() = cleared

    @OptIn(ExperimentalWebAuthnL3Api::class)
    public suspend fun encrypt(
        plaintext: ByteArray,
        associatedData: ByteArray? = null,
    ): PrfCiphertext {
        ensureValid()
        return PrfCrypto.encryptAesGcmWithRawKey(
            keyBytes = aesKeyBytes,
            plaintext = plaintext,
            associatedData = associatedData,
        )
    }

    @OptIn(ExperimentalWebAuthnL3Api::class)
    public suspend fun decrypt(
        ciphertext: PrfCiphertext,
    ): ByteArray {
        ensureValid()
        return PrfCrypto.decryptAesGcmWithRawKey(
            keyBytes = aesKeyBytes,
            ciphertext = ciphertext,
        )
    }

    public suspend fun encryptString(
        plaintext: String,
        associatedData: ByteArray? = null,
    ): PrfCiphertext {
        return encrypt(plaintext.encodeToByteArray(), associatedData)
    }

    public suspend fun decryptToString(
        ciphertext: PrfCiphertext,
    ): String {
        return decrypt(ciphertext).decodeToString()
    }

    public fun clear() {
        if (!cleared) {
            aesKeyBytes.fill(0)
            cleared = true
        }
    }

    private fun ensureValid() {
        check(!cleared) { "PrfCryptoSession has been cleared and cannot be used." }
    }
}
