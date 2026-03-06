package dev.webauthn.model

/** W3C WebAuthn L3: §5.4.2. PublicKeyCredentialRpEntity Dictionary */
public data class PublicKeyCredentialRpEntity(
    public val id: RpId,
    public val name: String,
)

/** W3C WebAuthn L3: §5.4.3. PublicKeyCredentialUserEntity Dictionary */
public data class PublicKeyCredentialUserEntity(
    public val id: UserHandle,
    public val name: String,
    public val displayName: String,
)

/** W3C WebAuthn L3: §5.4.4. PublicKeyCredentialParameters Dictionary */
public data class PublicKeyCredentialParameters(
    public val type: PublicKeyCredentialType,
    public val alg: Int,
)

/** W3C WebAuthn L3: §5.10.3. PublicKeyCredentialDescriptor Dictionary */
public data class PublicKeyCredentialDescriptor(
    public val type: PublicKeyCredentialType,
    public val id: CredentialId,
    public val transports: List<AuthenticatorTransport> = emptyList(),
)

/** W3C WebAuthn L3: §9.1. WebAuthn Extensions */
public data class AuthenticationExtensionsClientInputs(
    public val prf: PrfExtensionInput? = null,
    public val largeBlob: LargeBlobExtensionInput? = null,
    public val relatedOrigins: List<String>? = null,
)

/** W3C WebAuthn L3: §9.2.1. HMAC Secret Extension (prf) */
public data class PrfExtensionInput(
    public val eval: AuthenticationExtensionsPRFValues? = null,
    public val evalByCredential: Map<String, AuthenticationExtensionsPRFValues>? = null,
)

public data class AuthenticationExtensionsPRFValues(
    public val first: ByteArray,
    public val second: ByteArray? = null,
)

/** W3C WebAuthn L3: §9.2.2. Large blob storage extension (largeBlob) */
public data class LargeBlobExtensionInput(
    public val support: LargeBlobSupport? = null,
    public val read: Boolean? = null,
    public val write: ByteArray? = null,
) {
    public enum class LargeBlobSupport {
        REQUIRED,
        PREFERRED,
    }
}

/** W3C WebAuthn L3: §9.1. WebAuthn Extensions Output */
public data class AuthenticationExtensionsClientOutputs(
    public val prf: PrfExtensionOutput? = null,
    public val largeBlob: LargeBlobExtensionOutput? = null,
)

/** W3C WebAuthn L3: §9.2.1. HMAC Secret Extension (prf) Output */
public data class PrfExtensionOutput(
    public val enabled: Boolean? = null,
    public val results: AuthenticationExtensionsPRFValues? = null,
)

/** W3C WebAuthn L3: §9.2.2. Large blob storage extension (largeBlob) Output */
public data class LargeBlobExtensionOutput(
    public val supported: Boolean? = null,
    public val blob: ByteArray? = null,
    public val written: Boolean? = null,
)



/** W3C WebAuthn L3: §5.4. Options for Credential Creation (PublicKeyCredentialCreationOptions) */
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
    public val attestation: AttestationConveyancePreference? = null,
    public val extensions: AuthenticationExtensionsClientInputs? = null,
)

/** W3C WebAuthn L3: §5.5. Options for Assertion Generation (PublicKeyCredentialRequestOptions) */
public data class PublicKeyCredentialRequestOptions(
    public val challenge: Challenge,
    public val rpId: RpId,
    public val timeoutMs: Long? = null,
    public val allowCredentials: List<PublicKeyCredentialDescriptor> = emptyList(),
    public val userVerification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
    public val extensions: AuthenticationExtensionsClientInputs? = null,
)

/** W3C WebAuthn L3: §5.8.1. Client Data Used in WebAuthn Signatures (CollectedClientData) */
public data class CollectedClientData(
    public val type: String,
    public val challenge: Challenge,
    public val origin: Origin,
    public val crossOrigin: Boolean? = null,
)

/** W3C WebAuthn L3: §6.1. Authenticator Data */
public data class AuthenticatorData(
    public val rpIdHash: ByteArray,
    public val flags: Int,
    public val signCount: Long,
)

/** W3C WebAuthn L3: §6.5. Attested Credential Data */
public data class AttestedCredentialData(
    public val aaguid: ByteArray,
    public val credentialId: CredentialId,
    public val cosePublicKey: ByteArray,
)

/** W3C WebAuthn L3: §5.2. AuthenticatorAttestationResponse Interface */
public data class RegistrationResponse(
    public val credentialId: CredentialId,
    public val clientDataJson: Base64UrlBytes,
    public val attestationObject: Base64UrlBytes,
    public val rawAuthenticatorData: AuthenticatorData,
    public val attestedCredentialData: AttestedCredentialData,
    public val authenticatorAttachment: AuthenticatorAttachment? = null,
    public val extensions: AuthenticationExtensionsClientOutputs? = null,
)

/** W3C WebAuthn L3: §5.2.1. AuthenticatorAssertionResponse Interface */
public data class AuthenticationResponse(
    public val credentialId: CredentialId,
    public val clientDataJson: Base64UrlBytes,
    public val rawAuthenticatorData: Base64UrlBytes,
    public val authenticatorData: AuthenticatorData,
    public val signature: Base64UrlBytes,
    public val userHandle: UserHandle? = null,
    public val authenticatorAttachment: AuthenticatorAttachment? = null,
    public val extensions: AuthenticationExtensionsClientOutputs? = null,
)

