package dev.webauthn.documentation.examples

// docs-region client-core-controller
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult

/** Example backend adapter for the shared ceremony controller. */
class AccountServerClient : PasskeyServerClient<String, String> {
    override suspend fun getRegisterOptions(
        params: String,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        TODO("Call backend /registration/start")
    }

    override suspend fun finishRegister(
        params: String,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        TODO("Call backend /registration/finish")
    }

    override suspend fun getSignInOptions(
        params: String,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        TODO("Call backend /authentication/start")
    }

    override suspend fun finishSignIn(
        params: String,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        TODO("Call backend /authentication/finish")
    }
}

suspend fun runSignIn(controller: PasskeyController<String, String>, userId: String) {
    controller.signIn(userId)
    when (val state = controller.uiState.value) {
        is PasskeyControllerState.Success -> {
            // Continue into authenticated app flow.
        }
        is PasskeyControllerState.Failure -> {
            // Render or log state.error.message.
        }
        else -> Unit
    }
}
// docs-endregion client-core-controller
