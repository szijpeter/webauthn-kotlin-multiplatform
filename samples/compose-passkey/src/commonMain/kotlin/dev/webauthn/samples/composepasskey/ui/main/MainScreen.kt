package dev.webauthn.samples.composepasskey.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.model.StatusTone
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.Header
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
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Header(
            status = PasskeyDemoStatus(
                tone = StatusTone.SUCCESS,
                headline = "Signed in",
                detail = "PRF extension demo is ready.",
            ),
            onShowLogs = onShowLogs,
        )

        CapabilitiesCard(
            capabilities = state.capabilities,
        )

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

        SessionActionsCard(
            busy = state.busy,
            onLogout = onLogout,
        )
        Spacer(modifier = Modifier.height(20.dp))
    }
}
