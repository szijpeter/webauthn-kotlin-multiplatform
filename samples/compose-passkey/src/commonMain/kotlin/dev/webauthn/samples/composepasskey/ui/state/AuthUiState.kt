package dev.webauthn.samples.composepasskey.ui.state

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.toStatusPresentation

internal data class AuthUiState(
    val status: PasskeyDemoStatus = PasskeyControllerState.Idle.toStatusPresentation(),
    val actionsEnabled: Boolean = true,
    val runtimeHint: String? = null,
    val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    val prfBusy: Boolean = false,
    val prfPlaintext: String = "Top secret from passkey PRF",
    val prfStatusMessage: String = "Run Sign In + PRF to derive an in-memory AES session key.",
    val prfDecryptedText: String? = null,
    val prfSessionState: PrfCryptoDemoSessionState = PrfCryptoDemoSessionState.NoSession,
)
