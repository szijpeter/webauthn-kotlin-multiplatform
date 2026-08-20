package dev.webauthn.documentation.examples

// docs-region compose-client
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.KotlinxKtorPasskeyBackend
import dev.webauthn.network.kotlinx.RegistrationStartPayload
import kotlinx.coroutines.launch

@Composable
fun PasskeyEntryScreen(
    backend: KotlinxKtorPasskeyBackend,
    registerInput: RegistrationStartPayload,
    signInInput: AuthenticationStartPayload,
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
) {
    val scope = rememberCoroutineScope()
    val flow = PasskeyFlow(passkeyClient)

    fun onRegisterClick() = scope.launch {
        when (flow.register(registerInput, backend.registrationBackend())) {
            is CeremonyResult.Success -> Unit
            is CeremonyResult.Failure -> Unit
        }
    }

    fun onSignInClick() = scope.launch {
        when (flow.signIn(signInInput, backend.authenticationBackend())) {
            is CeremonyResult.Success -> Unit
            is CeremonyResult.Failure -> Unit
        }
    }

    // Wire onRegisterClick / onSignInClick to your Compose buttons and own presentation state.
}
// docs-endregion compose-client
