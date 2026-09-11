package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.mohamedrejeb.calf.ui.sheet.AdaptiveBottomSheet
import com.mohamedrejeb.calf.ui.sheet.AdaptiveSheetState
import dev.webauthn.samples.composepasskey.domain.model.DebugLogEntry

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DebugLogSheet(entries: List<DebugLogEntry>, sheetState: AdaptiveSheetState, onDismissRequest: () -> Unit) {
    AdaptiveBottomSheet(
        onDismissRequest = onDismissRequest,
        adaptiveSheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.background,
    ) {
        Column(Modifier.fillMaxHeight()) {
            Row(
                Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp, top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Debug logs",
                    Modifier.weight(1f).semantics { heading() },
                    style = MaterialTheme.typography.titleLarge,
                )
                TextButton(onClick = onDismissRequest) { Text("Done") }
            }
            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
            ) {
                if (entries.isEmpty()) {
                    item { Text("No events yet. Register or sign in to see activity.") }
                }
                itemsIndexed(entries, key = { _, entry -> entry.id }) { index, entry ->
                    val topRadius = if (index == 0) 16.dp else 0.dp
                    val bottomRadius = if (index == entries.lastIndex) 16.dp else 0.dp
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(topRadius, topRadius, bottomRadius, bottomRadius),
                    ) {
                        Column(Modifier.padding(horizontal = 16.dp)) {
                            DebugLogRow(entry, Modifier.padding(vertical = 12.dp))
                            if (index != entries.lastIndex) {
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            }
                        }
                    }
                }
            }
        }
    }
}
