package dev.webauthn.server

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.Base64UrlBytes

public fun base64UrlBytes(bytes: ByteArray): Base64UrlBytes = Base64UrlBytes.fromBytes(bytes)

public fun base64UrlBytes(vararg value: Int): Base64UrlBytes =
    Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })

public fun byteArraySignatureVerifier(
    block: (CoseAlgorithm, ByteArray, ByteArray, ByteArray) -> Boolean,
): SignatureVerifier {
    return SignatureVerifier { algorithm, publicKeyCose, data, signature ->
        block(algorithm, publicKeyCose.bytes(), data, signature)
    }
}
