package dev.webauthn.documentation.examples

// docs-region server-jvm-crypto
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier

/** Default JVM cryptographic dependencies for server ceremonies. */
data class ServerCrypto(
    val rpIdHasher: RpIdHasher,
    val signatureVerifier: SignatureVerifier,
    val attestationVerifier: AttestationVerifier,
)

fun serverCrypto(): ServerCrypto {
    val rpIdHasher = JvmRpIdHasher()
    val signatureVerifier = JvmSignatureVerifier()
    val attestationVerifier = StrictAttestationVerifier(signatureVerifier = signatureVerifier)
    return ServerCrypto(rpIdHasher, signatureVerifier, attestationVerifier)
}
// docs-endregion server-jvm-crypto
