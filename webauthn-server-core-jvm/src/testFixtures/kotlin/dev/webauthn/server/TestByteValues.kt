package dev.webauthn.server

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.ImmutableBytes

public fun immutableBytes(bytes: ByteArray): ImmutableBytes = ImmutableBytes.fromBytes(bytes)

public fun immutableBytes(vararg value: Int): ImmutableBytes =
    ImmutableBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })

public fun byteArraySignatureVerifier(
    block: (CoseAlgorithm, ByteArray, ByteArray, ByteArray) -> Boolean,
): SignatureVerifier {
    return SignatureVerifier { algorithm, publicKeyCose, data, signature ->
        block(algorithm, publicKeyCose.bytes(), data, signature)
    }
}
