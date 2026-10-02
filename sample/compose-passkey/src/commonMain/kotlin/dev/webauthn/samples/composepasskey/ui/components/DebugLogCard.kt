package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.data.logging.formatTimestampForDisplay
import dev.webauthn.samples.composepasskey.domain.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel

@Composable
fun DebugLogCard(entries: List<DebugLogEntry>) {
    DemoCard {
        Text("Debug logs", style = MaterialTheme.typography.titleLarge)
        if (entries.isEmpty()) {
            Text(
                "No events yet. Register or sign in to see activity.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        entries.forEach { entry ->
            DebugLogRow(entry)
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
internal fun DebugLogRow(entry: DebugLogEntry, modifier: Modifier = Modifier) {
    val color = when (entry.level) {
        DebugLogLevel.ERROR -> MaterialTheme.colorScheme.error
        DebugLogLevel.WARN -> MaterialTheme.colorScheme.onSecondaryContainer
        DebugLogLevel.INFO -> MaterialTheme.colorScheme.primary
        DebugLogLevel.DEBUG -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FlowRow(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(entry.level.name, color = color, style = MaterialTheme.typography.labelMedium)
                Text(
                    entry.source,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Text(
                entry.formatTimestampForDisplay(),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall,
            )
        }
        SelectionContainer {
            Text(entry.message, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        }
    }
}
