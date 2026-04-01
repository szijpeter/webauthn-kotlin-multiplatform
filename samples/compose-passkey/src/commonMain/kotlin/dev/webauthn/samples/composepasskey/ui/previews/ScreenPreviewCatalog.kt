package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.model.StatusTone
import dev.webauthn.samples.composepasskey.ui.screens.AuthScreen
import dev.webauthn.samples.composepasskey.ui.screens.MainScreen
import dev.webauthn.samples.composepasskey.ui.state.MainUiState
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography

@Preview(name = "Auth Screen - Idle")
@Composable
private fun AuthScreenIdlePreview() {
    PreviewSurface {
        AuthScreen(
            status = PasskeyDemoStatus(
                tone = StatusTone.IDLE,
                headline = "Ready",
                detail = "Tap Register or Sign In to begin.",
            ),
            actionsEnabled = true,
            canRegister = true,
            onShowLogs = {},
            onRegister = {},
            onSignIn = {},
        )
    }
}

@Preview(name = "Auth Screen - Busy")
@Composable
private fun AuthScreenBusyPreview() {
    PreviewSurface {
        AuthScreen(
            status = PasskeyDemoStatus(
                tone = StatusTone.WORKING,
                headline = "Platform prompt active",
                detail = "Complete the passkey prompt to continue.",
            ),
            actionsEnabled = false,
            canRegister = true,
            onShowLogs = {},
            onRegister = {},
            onSignIn = {},
        )
    }
}

@Preview(name = "Main Screen")
@Composable
private fun MainScreenPreview() {
    PreviewSurface {
        MainScreen(
            state = MainUiState(
                userName = "demo@local",
                capabilities = PasskeyCapabilities(
                    supported = setOf(
                        PasskeyCapability.Extension(WebAuthnExtension.Prf),
                        PasskeyCapability.PlatformFeature("securityKey"),
                    ),
                    platformVersionHints = listOf("android sdk=36", "play-services:available"),
                ),
                supportsPrf = true,
                sessionState = PrfCryptoDemoSessionState.SessionReady,
                plaintext = "The answer is 42",
                decryptedText = "The answer is 42",
                statusMessage = "Decrypt succeeded.",
            ),
            onShowLogs = {},
            onSignInWithPrf = {},
            onEncrypt = {},
            onDecrypt = {},
            onClearPrfSession = {},
            onPlaintextChange = {},
            onLogout = {},
        )
    }
}

@Composable
private fun PreviewSurface(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = EditorialPalette,
        typography = EditorialTypography,
    ) {
        Surface {
            content()
        }
    }
}
