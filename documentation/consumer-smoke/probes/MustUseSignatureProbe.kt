package smoke.server

import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.CosePublicKey

fun ignoreSignatureResult(
    signatureVerifier: SignatureVerifier,
    algorithm: CoseAlgorithm,
    publicKey: CosePublicKey,
    data: ByteArray,
    signature: ByteArray,
) {
    signatureVerifier.verify(algorithm, publicKey, data, signature)
}
