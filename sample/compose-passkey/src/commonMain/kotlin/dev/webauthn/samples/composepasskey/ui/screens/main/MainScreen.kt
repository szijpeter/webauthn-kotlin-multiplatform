package dev.webauthn.samples.composepasskey.ui.screens.main

import androidx.compose.runtime.Composable
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.ui.components.AdaptivePanels
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.ConfigurationCard
import dev.webauthn.samples.composepasskey.ui.components.DemoScreen
import dev.webauthn.samples.composepasskey.ui.components.Intro
import dev.webauthn.samples.composepasskey.ui.components.PrfCryptoCard
import dev.webauthn.samples.composepasskey.ui.components.SessionActionsCard

@Composable
internal fun MainScreen(
    state: MainUiState,
    onShowLogs: () -> Unit,
    onSignInWithPrf: () -> Unit,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onClearPrfSession: () -> Unit,
    onPlaintextChange: (String) -> Unit,
    onLogout: () -> Unit,
    config: PasskeyDemoConfig = PasskeyDemoConfig(),
) {
    DemoScreen(onShowLogs) {
        Intro("Signed in", state.userName)
        AdaptivePanels(
            primary = {
                PrfCryptoCard(
                    supportsPrf = state.supportsPrf,
                    actionsEnabled = !state.busy,
                    sessionState = state.sessionState,
                    plaintext = state.plaintext,
                    decryptedText = state.decryptedText,
                    statusMessage = state.statusMessage,
                    onPlaintextChange = onPlaintextChange,
                    onSignInWithPrf = onSignInWithPrf,
                    onEncrypt = onEncrypt,
                    onDecrypt = onDecrypt,
                    onClearSession = onClearPrfSession,
                )
            },
            secondary = {
                CapabilitiesCard(state.capabilities)
                ConfigurationCard(config)
                SessionActionsCard(busy = state.busy, onLogout = onLogout)
            },
        )
    }
}
