package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

internal actual class IosPasskeyDelegate actual constructor() {
    actual suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return PasskeyResult.Failure(
            PasskeyClientError.Platform(
                message = "AuthenticationServices bridge scaffolded; concrete ASAuthorization flow wiring is pending",
            ),
        )
    }

    actual suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return PasskeyResult.Failure(
            PasskeyClientError.Platform(
                message = "AuthenticationServices bridge scaffolded; concrete ASAuthorization flow wiring is pending",
            ),
        )
    }
}
