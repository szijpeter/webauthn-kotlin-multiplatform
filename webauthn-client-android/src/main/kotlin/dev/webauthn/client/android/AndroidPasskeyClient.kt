package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CredentialManager
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

public class AndroidPasskeyClient(
    context: Context,
) : PasskeyClient {
    private val credentialManager: CredentialManager = CredentialManager.create(context)

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        if (options.pubKeyCredParams.isEmpty()) {
            return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("pubKeyCredParams must not be empty"))
        }

        return PasskeyResult.Failure(
            PasskeyClientError.Platform(
                message = "Credential Manager integration is scaffolded but not yet wired to concrete request builders",
            ),
        )
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        if (options.allowCredentials.isEmpty()) {
            return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("allowCredentials must not be empty"))
        }

        return PasskeyResult.Failure(
            PasskeyClientError.Platform(
                message = "Credential Manager integration is scaffolded but not yet wired to concrete request builders",
            ),
        )
    }
}
