package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.model.StatusTone
import dev.webauthn.samples.composepasskey.ui.screens.AuthScreen
import dev.webauthn.samples.composepasskey.ui.screens.LoggedInScreen
import dev.webauthn.samples.composepasskey.ui.state.AuthUiState
import dev.webauthn.samples.composepasskey.ui.state.LoggedInUiState
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography
import kotlin.time.Instant

@Preview(name = "Auth Screen - Idle")
@Composable
private fun AuthScreenIdlePreview() {
    PreviewSurface {
        AuthScreen(
            state = AuthUiState(
                status = PasskeyDemoStatus(
                    tone = StatusTone.IDLE,
                    headline = "Ready",
                    detail = "Tap Register or Sign In to begin.",
                ),
                actionsEnabled = true,
            ),
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
            state = AuthUiState(
                status = PasskeyDemoStatus(
                    tone = StatusTone.WORKING,
                    headline = "Platform prompt active",
                    detail = "Complete the passkey prompt to continue.",
                ),
                actionsEnabled = false,
                runtimeHint = "Security key provider appears unavailable on this device.",
            ),
            onRegister = {},
            onSignIn = {},
        )
    }
}

@Preview(name = "Logged-In Screen")
@Composable
private fun LoggedInScreenPreview() {
    PreviewSurface {
        LoggedInScreen(
            state = LoggedInUiState(
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
                plaintext = "Top secret from passkey PRF",
                decryptedText = "Top secret from passkey PRF",
                statusMessage = "Decrypt succeeded.",
            ),
            debugEntries = listOf(
                DebugLogEntry(
                    id = 1L,
                    timestamp = Instant.parse("2026-03-30T09:41:22Z"),
                    level = DebugLogLevel.INFO,
                    source = "prf",
                    message = "Session ready (fp=8f2c...).",
                ),
                DebugLogEntry(
                    id = 2L,
                    timestamp = Instant.parse("2026-03-30T09:41:25Z"),
                    level = DebugLogLevel.DEBUG,
                    source = "controller",
                    message = "State moved to IDLE.",
                ),
            ),
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
