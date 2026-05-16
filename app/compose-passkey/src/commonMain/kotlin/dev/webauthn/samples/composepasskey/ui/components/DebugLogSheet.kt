package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetState
import androidx.compose.runtime.Composable
import dev.webauthn.samples.composepasskey.domain.model.DebugLogEntry

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DebugLogSheet(
    entries: List<DebugLogEntry>,
    sheetState: SheetState,
    onDismissRequest: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismissRequest,
        sheetState = sheetState,
    ) {
        DebugLogCard(entries = entries)
    }
}
