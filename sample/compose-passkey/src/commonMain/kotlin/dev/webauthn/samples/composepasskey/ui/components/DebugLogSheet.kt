package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.domain.model.DebugLogEntry

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DebugLogSheet(entries: List<DebugLogEntry>, sheetState: SheetState, onDismissRequest: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismissRequest, sheetState = sheetState) {
        Column(Modifier.fillMaxHeight()) {
            TextButton(onClick = onDismissRequest, modifier = Modifier.padding(horizontal = 12.dp)) { Text("Done") }
            Text("Debug logs", Modifier.padding(horizontal = 24.dp), style = MaterialTheme.typography.headlineSmall)
            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f),
                contentPadding = PaddingValues(24.dp),
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                if (entries.isEmpty()) {
                    item { Text("No events yet. Register or sign in to see activity.") }
                }
                items(entries.asReversed(), key = { it.id }) { DebugLogRow(it) }
            }
        }
    }
}
