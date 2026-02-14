package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

public class IosPasskeyClient : PasskeyClient {
    private val delegate: IosPasskeyDelegate = IosPasskeyDelegate()

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return delegate.createCredential(options)
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return delegate.getAssertion(options)
    }
}

internal expect class IosPasskeyDelegate() {
    suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse>

    suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse>
}
