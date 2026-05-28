package dev.webauthn.samples.passkeycli

import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto

internal interface AuthenticatorAdapter {
    suspend fun createCredential(
        origin: String,
        options: PublicKeyCredentialCreationOptionsDto,
    ): RegistrationResponseDto

    suspend fun getAssertion(
        origin: String,
        options: PublicKeyCredentialRequestOptionsDto,
    ): AuthenticationResponseDto
}
