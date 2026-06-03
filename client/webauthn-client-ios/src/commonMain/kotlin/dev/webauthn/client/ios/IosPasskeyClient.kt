package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

/** iOS [PasskeyClient] implementation delegated to native AuthenticationServices bridge. */
public class IosPasskeyClient : PasskeyClient by IosPasskeyClientImpl()

internal expect class IosPasskeyClientImpl() : PasskeyClient {
    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse>

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse>
}
