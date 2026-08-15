package dev.webauthn.documentation.examples

// docs-region compose-client
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.client.compose.rememberPasskeyFlow
import kotlinx.coroutines.launch

@Composable
fun <Input, State, Output> PasskeyRegistrationEntryScreen(
    backend: RegistrationBackend<Input, State, Output>,
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
    input: Input,
) {
    val scope = rememberCoroutineScope()
    val flow = rememberPasskeyFlow(passkeyClient)
    var phase by remember { mutableStateOf<PasskeyPhase?>(null) }
    var status by remember { mutableStateOf("Ready") }

    fun onRegisterClick() = scope.launch {
        when (val result = flow.register(input, backend, onPhaseChanged = { phase = it })) {
            is CeremonyResult.Success -> status = "Registration completed"
            is CeremonyResult.Failure -> status = "Registration failed: ${result.error}"
        }
    }

    // Render phase and status; disable repeated taps while phase is non-null.
    // Wire onRegisterClick to a Compose button.
}
// docs-endregion compose-client
