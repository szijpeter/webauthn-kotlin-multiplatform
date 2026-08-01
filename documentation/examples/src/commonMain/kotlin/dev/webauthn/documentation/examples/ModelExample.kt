package dev.webauthn.documentation.examples

// docs-region model-request-options
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialDescriptor
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.RpId
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.ValidationResult

fun buildSignInOptions(
    challengeBytes: ByteArray,
    rpIdFromRequest: String,
    storedCredentialId: String,
): ValidationResult<PublicKeyCredentialRequestOptions> {
    val rpId = RpId.parse(rpIdFromRequest)
    val credentialId = CredentialId.parse(storedCredentialId)

    if (rpId is ValidationResult.Invalid) return rpId
    if (credentialId is ValidationResult.Invalid) return credentialId

    val options = PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(challengeBytes),
        rpId = (rpId as ValidationResult.Valid).value,
        allowCredentials = [
            PublicKeyCredentialDescriptor(
                type = PublicKeyCredentialType.PUBLIC_KEY,
                id = (credentialId as ValidationResult.Valid).value,
            ),
        ],
        userVerification = UserVerificationRequirement.PREFERRED,
    )
    return ValidationResult.Valid(options)
}
// docs-endregion model-request-options
