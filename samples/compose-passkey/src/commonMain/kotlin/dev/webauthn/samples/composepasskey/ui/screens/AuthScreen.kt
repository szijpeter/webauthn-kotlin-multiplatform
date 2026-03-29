package dev.webauthn.samples.composepasskey.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.ui.components.ActionsCard
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.DebugLogCard
import dev.webauthn.samples.composepasskey.ui.components.Header
import dev.webauthn.samples.composepasskey.ui.components.PrfCryptoCard
import dev.webauthn.samples.composepasskey.ui.state.AuthUiState

@Composable
internal fun AuthScreen(
    state: AuthUiState,
    debugEntries: List<DebugLogEntry>,
    onRegister: () -> Unit,
    onSignIn: () -> Unit,
    onSignInWithPrf: () -> Unit,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onClearPrfSession: () -> Unit,
    onPlaintextChange: (String) -> Unit,
) {
    val prfCapability = remember { PasskeyCapability.Extension(WebAuthnExtension.Prf) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Header(status = state.status)

        if (state.runtimeHint != null) {
            Text(text = state.runtimeHint)
        }

        CapabilitiesCard(
            capabilities = state.capabilities,
        )

        ActionsCard(
            actionsEnabled = state.actionsEnabled && !state.prfBusy,
            onRegister = onRegister,
            onSignIn = onSignIn,
        )

        PrfCryptoCard(
            supportsPrf = state.capabilities.supports(prfCapability),
            actionsEnabled = state.actionsEnabled && !state.prfBusy,
            sessionState = state.prfSessionState,
            plaintext = state.prfPlaintext,
            decryptedText = state.prfDecryptedText,
            statusMessage = state.prfStatusMessage,
            onPlaintextChange = onPlaintextChange,
            onSignInWithPrf = onSignInWithPrf,
            onEncrypt = onEncrypt,
            onDecrypt = onDecrypt,
            onClearSession = onClearPrfSession,
        )

        DebugLogCard(entries = debugEntries)
        Spacer(modifier = Modifier.height(20.dp))
    }
}
