package dev.webauthn.samples.composepasskey.ui.screens.auth

import androidx.compose.runtime.Composable
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.ui.components.ActionsCard
import dev.webauthn.samples.composepasskey.ui.components.AdaptivePanels
import dev.webauthn.samples.composepasskey.ui.components.ConfigurationCard
import dev.webauthn.samples.composepasskey.ui.components.DemoScreen
import dev.webauthn.samples.composepasskey.ui.components.Intro
import dev.webauthn.samples.composepasskey.ui.components.StatusCard

@Composable
internal fun AuthScreen(
    status: PasskeyDemoStatus,
    actionsEnabled: Boolean,
    canRegister: Boolean,
    onShowLogs: () -> Unit,
    onRegister: () -> Unit,
    onSignIn: () -> Unit,
    config: PasskeyDemoConfig = PasskeyDemoConfig(),
) {
    DemoScreen(onShowLogs) {
        AdaptivePanels(
            primary = {
                Intro(
                    "Passkey authentication",
                    "Register a passkey or sign in with an existing account.",
                )
                StatusCard(status)
            },
            secondary = {
                ActionsCard(
                    actionsEnabled = actionsEnabled,
                    showRegister = canRegister,
                    onRegister = onRegister,
                    onSignIn = onSignIn,
                )
                ConfigurationCard(config)
            },
        )
    }
}
