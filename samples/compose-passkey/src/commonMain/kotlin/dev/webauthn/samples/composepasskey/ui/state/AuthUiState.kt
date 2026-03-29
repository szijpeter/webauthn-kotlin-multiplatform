package dev.webauthn.samples.composepasskey.ui.state

import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.toStatusPresentation

internal data class AuthUiState(
    val status: PasskeyDemoStatus = PasskeyControllerState.Idle.toStatusPresentation(),
    val actionsEnabled: Boolean = true,
    val runtimeHint: String? = null,
)
