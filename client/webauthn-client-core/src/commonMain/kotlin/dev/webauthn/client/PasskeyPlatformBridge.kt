@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

/** Platform bridge contract implemented by target-specific modules. */
public interface PasskeyPlatformBridge {
    public suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse

    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
        createOptions: PasskeyCreateOptions,
    ): RegistrationResponse {
        if (createOptions == PasskeyCreateOptions.Default) {
            return createCredential(options)
        }
        throw UnsupportedOperationException("Passkey create option ${createOptions.mediation} is not supported")
    }

    public suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse

    public fun mapPlatformError(throwable: Throwable): PasskeyClientError

    public suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
}
