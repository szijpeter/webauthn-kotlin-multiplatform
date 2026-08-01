package smoke.server

import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier

fun serverSmoke(): String {
    val rpIdHasher = JvmRpIdHasher()
    val signatureVerifier = JvmSignatureVerifier()
    val attestationVerifier = StrictAttestationVerifier(signatureVerifier)
    return "${rpIdHasher::class.simpleName}:${attestationVerifier::class.simpleName}"
}
