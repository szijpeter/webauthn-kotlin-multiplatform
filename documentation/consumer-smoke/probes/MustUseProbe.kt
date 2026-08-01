package smoke.server

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.CosePublicKey

fun ignoreSecurityResults(
    input: RegistrationValidationInput,
    signatureVerifier: SignatureVerifier,
    algorithm: CoseAlgorithm,
    publicKey: CosePublicKey,
    data: ByteArray,
    signature: ByteArray,
) {
    WebAuthnCoreValidator.validateRegistration(input)
    signatureVerifier.verify(algorithm, publicKey, data, signature)
}
