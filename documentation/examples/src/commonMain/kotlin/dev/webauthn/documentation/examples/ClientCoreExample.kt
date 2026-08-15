package dev.webauthn.documentation.examples

// docs-region client-core-controller
import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawRegistrationResponse

/** Example typed backend for the shared ceremony flow. */
class AccountRegistrationBackend : RegistrationBackend<String, String, PasskeyFinishResult> {
    override suspend fun start(input: String): CeremonyStart<String, PublicKeyCredentialCreationOptions> {
        TODO("Call backend /registration/start")
    }

    override suspend fun finish(state: String, response: RawRegistrationResponse): PasskeyFinishResult {
        TODO("Call backend /registration/finish")
    }

}

class AccountAuthenticationBackend : AuthenticationBackend<String, String, PasskeyFinishResult> {
    override suspend fun start(input: String): CeremonyStart<String, PublicKeyCredentialRequestOptions> {
        TODO("Call backend /authentication/start")
    }

    override suspend fun finish(state: String, response: RawAuthenticationResponse): PasskeyFinishResult {
        TODO("Call backend /authentication/finish")
    }
}

suspend fun runSignIn(flow: PasskeyFlow, backend: AccountAuthenticationBackend, userId: String) {
    when (flow.signIn(input = userId, backend = backend)) {
        is CeremonyResult.Success -> {
            // Continue into authenticated app flow.
        }
        is CeremonyResult.Failure -> {
            // Render or log the caller-owned failure state.
        }
    }
}
// docs-endregion client-core-controller
