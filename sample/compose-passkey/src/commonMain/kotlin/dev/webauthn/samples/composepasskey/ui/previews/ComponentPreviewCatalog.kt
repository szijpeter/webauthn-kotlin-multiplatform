package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.domain.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.model.StatusTone
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.ui.components.ActionsCard
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.DebugLogCard
import dev.webauthn.samples.composepasskey.ui.components.Header
import dev.webauthn.samples.composepasskey.ui.components.PrfCryptoCard
import dev.webauthn.samples.composepasskey.ui.components.SessionActionsCard
import dev.webauthn.samples.composepasskey.ui.theme.Palette
import dev.webauthn.samples.composepasskey.ui.theme.Typography
import kotlin.time.Instant

@Preview(name = "Header")
@Composable
private fun HeaderPreview() {
    PreviewSurface {
        Header(
            status = PasskeyDemoStatus(
                tone = StatusTone.SUCCESS,
                headline = "Signed in",
                detail = "Extension demo area is now active.",
            ),
        )
    }
}

@Preview(name = "Actions Card")
@Composable
private fun ActionsCardPreview() {
    PreviewSurface {
        ActionsCard(
            actionsEnabled = true,
            onRegister = {},
            onSignIn = {},
        )
    }
}

@Preview(name = "Capabilities Card")
@Composable
private fun CapabilitiesCardPreview() {
    PreviewSurface {
        CapabilitiesCard(
            capabilities = PasskeyCapabilities(
                supported = setOf(
                    PasskeyCapability.Extension(WebAuthnExtension.Prf),
                    PasskeyCapability.Extension(WebAuthnExtension.LargeBlob),
                ),
                platformVersionHints = listOf("ios 18.2", "platform passkeys enabled"),
            ),
        )
    }
}

@Preview(name = "PRF Crypto Card")
@Composable
private fun PrfCryptoCardPreview() {
    PreviewSurface {
        PrfCryptoCard(
            modifier = Modifier.fillMaxWidth(),
            supportsPrf = true,
            actionsEnabled = true,
            sessionState = PrfCryptoDemoSessionState.CiphertextReady,
            plaintext = "The answer is 42",
            decryptedText = "The answer is 42",
            statusMessage = "Encrypted 27 chars to 32 bytes.",
            onPlaintextChange = {},
            onSignInWithPrf = {},
            onEncrypt = {},
            onDecrypt = {},
            onClearSession = {},
        )
    }
}

@Preview(name = "Session Actions Card")
@Composable
private fun SessionActionsCardPreview() {
    PreviewSurface {
        SessionActionsCard(
            busy = false,
            onLogout = {},
        )
    }
}

@Preview(name = "Debug Log Card")
@Composable
private fun DebugLogCardPreview() {
    PreviewSurface {
        DebugLogCard(
            entries = listOf(
                DebugLogEntry(
                    id = 1L,
                    timestamp = Instant.parse("2026-03-30T10:01:10Z"),
                    level = DebugLogLevel.INFO,
                    source = "action",
                    message = "Sign In tapped",
                ),
                DebugLogEntry(
                    id = 2L,
                    timestamp = Instant.parse("2026-03-30T10:01:11Z"),
                    level = DebugLogLevel.WARN,
                    source = "capabilities",
                    message = "PRF extension not supported on this profile.",
                ),
                DebugLogEntry(
                    id = 3L,
                    timestamp = Instant.parse("2026-03-30T10:01:13Z"),
                    level = DebugLogLevel.ERROR,
                    source = "http",
                    message = "Request failed: 401 unauthorized",
                ),
            ),
        )
    }
}

@Preview(name = "Preview Catalog")
@Composable
private fun ComponentCatalogPreview() {
    PreviewSurface {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            Header(
                status = PasskeyDemoStatus(
                    tone = StatusTone.IDLE,
                    headline = "Ready",
                ),
            )
            SpacerBlock()
            ActionsCard(actionsEnabled = true, onRegister = {}, onSignIn = {})
            SpacerBlock()
            SessionActionsCard(busy = false, onLogout = {})
        }
    }
}

@Composable
private fun SpacerBlock() {
    Spacer(
        modifier = Modifier.size(12.dp),
    )
}

@Composable
private fun PreviewSurface(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = Palette,
        typography = Typography,
    ) {
        Surface {
            content()
        }
    }
}
