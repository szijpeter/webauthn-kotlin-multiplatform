package dev.webauthn.model

public data class PublicKeyCredentialRpEntity(
    public val id: RpId,
    public val name: String,
)

public data class PublicKeyCredentialUserEntity(
    public val id: UserHandle,
    public val name: String,
    public val displayName: String,
)

public data class PublicKeyCredentialParameters(
    public val type: PublicKeyCredentialType,
    public val alg: Int,
)

public data class PublicKeyCredentialDescriptor(
    public val type: PublicKeyCredentialType,
    public val id: CredentialId,
)

public data class AuthenticationExtensionsClientInputs(
    public val prf: PrfExtensionInput? = null,
    public val largeBlob: LargeBlobExtensionInput? = null,
)

public data class PrfExtensionInput(
    public val enabled: Boolean,
)

public data class LargeBlobExtensionInput(
    public val support: LargeBlobSupport,
) {
    public enum class LargeBlobSupport {
        REQUIRED,
        PREFERRED,
    }
}

public data class PublicKeyCredentialCreationOptions(
    public val rp: PublicKeyCredentialRpEntity,
    public val user: PublicKeyCredentialUserEntity,
    public val challenge: Challenge,
    public val pubKeyCredParams: List<PublicKeyCredentialParameters>,
    public val timeoutMs: Long? = null,
    public val excludeCredentials: List<PublicKeyCredentialDescriptor> = emptyList(),
    public val authenticatorAttachment: AuthenticatorAttachment? = null,
    public val residentKey: ResidentKeyRequirement = ResidentKeyRequirement.PREFERRED,
    public val userVerification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
    public val extensions: AuthenticationExtensionsClientInputs? = null,
)

public data class PublicKeyCredentialRequestOptions(
    public val challenge: Challenge,
    public val rpId: RpId,
    public val timeoutMs: Long? = null,
    public val allowCredentials: List<PublicKeyCredentialDescriptor> = emptyList(),
    public val userVerification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
    public val extensions: AuthenticationExtensionsClientInputs? = null,
)

public data class CollectedClientData(
    public val type: String,
    public val challenge: Challenge,
    public val origin: Origin,
    public val crossOrigin: Boolean? = null,
)

public data class AuthenticatorData(
    public val rpIdHash: ByteArray,
    public val flags: Int,
    public val signCount: Long,
)

public data class AttestedCredentialData(
    public val credentialId: CredentialId,
    public val cosePublicKey: ByteArray,
)

public data class RegistrationResponse(
    public val credentialId: CredentialId,
    public val clientDataJson: Base64UrlBytes,
    public val attestationObject: Base64UrlBytes,
    public val rawAuthenticatorData: AuthenticatorData,
    public val attestedCredentialData: AttestedCredentialData,
)

public data class AuthenticationResponse(
    public val credentialId: CredentialId,
    public val clientDataJson: Base64UrlBytes,
    public val authenticatorData: AuthenticatorData,
    public val signature: Base64UrlBytes,
    public val userHandle: UserHandle? = null,
)
