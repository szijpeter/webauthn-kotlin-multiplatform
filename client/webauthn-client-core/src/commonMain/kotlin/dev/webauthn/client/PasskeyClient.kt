@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.RegistrationResponse

/** Public cross-platform API for WebAuthn registration and authentication ceremonies. */
public interface PasskeyClient {
    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.create)
     */
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse>

    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.create)
     * with platform mediation hints.
     */
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
        createOptions: PasskeyCreateOptions,
    ): PasskeyResult<RegistrationResponse> {
        if (createOptions == PasskeyCreateOptions.Default) {
            return createCredential(options)
        }
        return PasskeyResult.Failure(
            PasskeyClientError.Platform("Passkey create option ${createOptions.mediation} is not supported"),
        )
    }

    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.get)
     */
    public suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse>

    public suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
}
