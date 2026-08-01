package dev.webauthn.documentation.examples

// docs-region compose-client
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.client.compose.rememberPasskeyController
import kotlinx.coroutines.launch

@Composable
fun <RegisterParams, SignInParams> PasskeyEntryScreen(
    serverClient: PasskeyServerClient<RegisterParams, SignInParams>,
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
    registerParams: RegisterParams,
    signInParams: SignInParams,
) {
    val scope = rememberCoroutineScope()
    val controller = rememberPasskeyController(
        serverClient = serverClient,
        passkeyClient = passkeyClient,
    )
    val state by controller.uiState.collectAsState()

    fun onRegisterClick() = scope.launch { controller.register(registerParams) }
    fun onSignInClick() = scope.launch { controller.signIn(signInParams) }

    when (val current = state) {
        PasskeyControllerState.Idle -> Unit
        is PasskeyControllerState.InProgress -> {
            // Show loading state and disable repeated taps.
        }
        is PasskeyControllerState.Success -> {
            // Navigate or refresh session state.
        }
        is PasskeyControllerState.Failure -> {
            // Surface current.error.message in UI.
        }
    }

    // Wire onRegisterClick / onSignInClick to your Compose buttons.
}
// docs-endregion compose-client
