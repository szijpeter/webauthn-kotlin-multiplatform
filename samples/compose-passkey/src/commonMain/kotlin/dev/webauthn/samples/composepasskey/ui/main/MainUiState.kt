package dev.webauthn.samples.composepasskey.ui.main

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState

internal data class MainUiState(
    val userName: String = "",
    val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    val busy: Boolean = false,
    val supportsPrf: Boolean = false,
    val sessionState: PrfCryptoDemoSessionState = PrfCryptoDemoSessionState.NoSession,
    val plaintext: String = "The answer is 42",
    val decryptedText: String? = null,
    val statusMessage: String = "Run Sign In + PRF to derive an in-memory AES session key.",
)
