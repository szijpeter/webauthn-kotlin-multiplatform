package dev.webauthn.samples.composepasskey.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.model.StatusTone
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.DebugLogSheet
import dev.webauthn.samples.composepasskey.ui.components.Header
import dev.webauthn.samples.composepasskey.ui.components.PrfCryptoCard
import dev.webauthn.samples.composepasskey.ui.components.SessionActionsCard
import dev.webauthn.samples.composepasskey.ui.state.LoggedInUiState

@Composable
@OptIn(ExperimentalMaterial3Api::class)
internal fun LoggedInScreen(
    state: LoggedInUiState,
    debugEntries: List<DebugLogEntry>,
    onSignInWithPrf: () -> Unit,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onClearPrfSession: () -> Unit,
    onPlaintextChange: (String) -> Unit,
    onLogout: () -> Unit,
) {
    var showDebugSheet by remember { mutableStateOf(false) }
    val debugSheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    if (showDebugSheet) {
        DebugLogSheet(
            entries = debugEntries,
            sheetState = debugSheetState,
            onDismissRequest = { showDebugSheet = false },
        )
    }

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
                detail = "Extension demo area is now active.",
            ),
            onTitleDoubleTap = { showDebugSheet = true },
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
