package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.Origin
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.ValidationResult

public enum class CeremonyType {
    REGISTRATION,
    AUTHENTICATION,
}

public data class ChallengeSession(
    public val challenge: Challenge,
    public val rpId: RpId,
    public val origin: Origin,
    public val userName: String,
    public val createdAtEpochMs: Long,
    public val expiresAtEpochMs: Long,
    public val type: CeremonyType,
    public val extensions: AuthenticationExtensionsClientInputs? = null,
)


public data class RegistrationValidationInput(
    public val options: PublicKeyCredentialCreationOptions,
    public val response: RegistrationResponse,
    public val clientData: CollectedClientData,
    public val expectedOrigin: Origin,
    public val allowedOrigins: Set<Origin> = emptySet(),
    public val userVerificationPolicy: UserVerificationPolicy = UserVerificationPolicy.PREFERRED,
)

public data class AuthenticationValidationInput(
    public val options: PublicKeyCredentialRequestOptions,
    public val response: AuthenticationResponse,
    public val clientData: CollectedClientData,
    public val expectedOrigin: Origin,
    public val allowedOrigins: Set<Origin> = emptySet(),
    public val previousSignCount: Long,
    public val userVerificationPolicy: UserVerificationPolicy = UserVerificationPolicy.PREFERRED,
)

public data class RegistrationValidationOutput(
    public val credentialId: CredentialId,
    public val signCount: Long,
    public val extensions: AuthenticationExtensionsClientOutputs? = null,
)

public data class AuthenticationValidationOutput(
    public val credentialId: CredentialId,
    public val signCount: Long,
    public val extensions: AuthenticationExtensionsClientOutputs? = null,
)


@ExperimentalWebAuthnL3Api
public interface WebAuthnExtensionHook {
    public fun validateRegistrationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit>

    public fun validateAuthenticationExtensions(
        inputs: AuthenticationExtensionsClientInputs?,
        outputs: AuthenticationExtensionsClientOutputs?,
    ): ValidationResult<Unit>
}

