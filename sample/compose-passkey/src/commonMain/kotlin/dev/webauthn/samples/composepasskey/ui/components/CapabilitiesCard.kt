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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PlatformCapability
import dev.webauthn.model.WebAuthnExtension

@Composable
fun CapabilitiesCard(
    capabilities: PasskeyCapabilities,
) {
    val prfCapability = remember { PasskeyCapability.Extension(WebAuthnExtension.Prf) }
    val largeBlobCapability = remember { PasskeyCapability.Extension(WebAuthnExtension.LargeBlob) }
    val securityKeyCapability = remember { PasskeyCapability.Platform(PlatformCapability.SecurityKey) }

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
                CapabilityChip("PRF", capabilities.supportOf(prfCapability))
                CapabilityChip("Large Blob", capabilities.supportOf(largeBlobCapability))
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("Security Key", capabilities.supportOf(securityKeyCapability))
            }
            Text(
                text = "Unknown means the client cannot determine support reliably.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CapabilityChip(label: String, support: CapabilitySupport) {
    val color = when (support) {
        CapabilitySupport.SUPPORTED -> Color(0xFF9BC08E)
        CapabilitySupport.UNSUPPORTED -> Color(0xFFD4D9DD)
        CapabilitySupport.UNKNOWN -> Color(0xFFF4D6A0)
    }
    val indicatorColor = when (support) {
        CapabilitySupport.SUPPORTED -> Color(0xFF1B4D2C)
        CapabilitySupport.UNSUPPORTED -> Color(0xFF5E6C77)
        CapabilitySupport.UNKNOWN -> Color(0xFF7A4D00)
    }
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
                    .background(indicatorColor),
            )
            Text(
                text = "$label: ${support.name.lowercase()}",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF1B2C39),
            )
        }
    }
}
