@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse

/** Public cross-platform API for WebAuthn registration and authentication ceremonies. */
public interface PasskeyClient {
    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.create)
     */
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RawRegistrationResponse>

    /**
     * Creates a credential with cross-platform ceremony hints such as conditional mediation.
     *
     * Implementations that do not override this method support [PasskeyCreateOptions.Default]
     * only and return a typed failure for other option sets.
     */
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
        createOptions: PasskeyCreateOptions,
    ): PasskeyResult<RawRegistrationResponse> {
        if (createOptions == PasskeyCreateOptions.Default) {
            return createCredential(options)
        }
        return PasskeyResult.Failure(
            PasskeyClientError.Platform(
                "Passkey create mediation ${createOptions.mediation} is not supported",
            ),
        )
    }

    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.get)
     */
    public suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<RawAuthenticationResponse>

    public suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
}
