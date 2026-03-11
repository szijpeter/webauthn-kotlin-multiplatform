@file:Suppress("MagicNumber")

package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import dev.webauthn.client.PasskeyCapabilities

@Composable
public fun CapabilitiesCard(
    capabilities: PasskeyCapabilities,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Capabilities", style = MaterialTheme.typography.titleMedium)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("PRF", capabilities.supportsPrf)
                CapabilityChip("Large Blob Read", capabilities.supportsLargeBlobRead)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("Large Blob Write", capabilities.supportsLargeBlobWrite)
                CapabilityChip("Security Key", capabilities.supportsSecurityKey)
            }
            Text(
                text = if (capabilities.platformVersionHints.isEmpty()) {
                    "No platform hints reported"
                } else {
                    capabilities.platformVersionHints.joinToString()
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CapabilityChip(label: String, enabled: Boolean) {
    val color = if (enabled) Color(0xFF9BC08E) else Color(0xFFD4D9DD)
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = color,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .clip(CircleShape)
                    .background(if (enabled) Color(0xFF1B4D2C) else Color(0xFF5E6C77)),
            )
            Text(
                text = "$label: ${if (enabled) "yes" else "no"}",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF1B2C39),
            )
        }
    }
}
