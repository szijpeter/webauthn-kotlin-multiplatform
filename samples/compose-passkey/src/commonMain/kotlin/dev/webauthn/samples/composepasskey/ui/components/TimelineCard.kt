package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.model.PasskeyDemoLogEntry
import dev.webauthn.samples.composepasskey.model.StatusTone

@Composable
public fun TimelineCard(logs: List<PasskeyDemoLogEntry>) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Timeline", style = MaterialTheme.typography.titleMedium)
            AnimatedContent(targetState = logs, label = "logs") { entries ->
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (entries.isEmpty()) {
                        Text(
                            text = "No events yet.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        entries.forEach { entry ->
                            val stripe = when (entry.tone) {
                                StatusTone.IDLE -> Color(0xFF94A3AF)
                                StatusTone.WORKING -> Color(0xFFCEA650)
                                StatusTone.SUCCESS -> Color(0xFF5A9E62)
                                StatusTone.WARNING -> Color(0xFFC4804A)
                                StatusTone.ERROR -> Color(0xFFB54F60)
                            }
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(MaterialTheme.colorScheme.surfaceVariant)
                                    .padding(10.dp),
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                verticalAlignment = Alignment.Top,
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(width = 4.dp, height = 36.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(stripe),
                                )
                                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text(
                                        text = entry.timestamp,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Text(
                                        text = entry.message,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
