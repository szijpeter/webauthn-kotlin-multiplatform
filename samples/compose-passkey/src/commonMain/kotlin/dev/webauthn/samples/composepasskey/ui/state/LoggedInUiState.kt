package dev.webauthn.samples.composepasskey.ui.state

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState

internal data class LoggedInUiState(
    val userName: String = "",
    val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    val busy: Boolean = false,
    val supportsPrf: Boolean = false,
    val sessionState: PrfCryptoDemoSessionState = PrfCryptoDemoSessionState.NoSession,
    val plaintext: String = "The answer is 42",
    val decryptedText: String? = null,
    val statusMessage: String = "Run Sign In + PRF to derive an in-memory AES session key.",
)
