package dev.webauthn.documentation.examples

// docs-region crypto-rp-id-hasher
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.model.RpIdHash

fun rpIdHasher(sha256: (ByteArray) -> ByteArray): RpIdHasher {
    return RpIdHasher { rpId ->
        val rpIdSha256 = sha256(rpId.encodeToByteArray())
        RpIdHash.fromBytes(rpIdSha256)
    }
}
// docs-endregion crypto-rp-id-hasher
