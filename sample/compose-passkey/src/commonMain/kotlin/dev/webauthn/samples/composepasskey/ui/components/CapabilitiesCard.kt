package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PlatformCapability
import dev.webauthn.model.WebAuthnExtension

@Composable
fun CapabilitiesCard(capabilities: PasskeyCapabilities) {
    DemoCard {
        Text(
            "Device capabilities",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.semantics { heading() },
        )
        CapabilityRow("PRF encryption", capabilities.supportOf(PasskeyCapability.Extension(WebAuthnExtension.Prf)))
        CapabilityRow("Large blob", capabilities.supportOf(PasskeyCapability.Extension(WebAuthnExtension.LargeBlob)))
        CapabilityRow("Security key",
            capabilities.supportOf(PasskeyCapability.Platform(PlatformCapability.SecurityKey)))
        Text(
            "Reported by your platform. Individual passkey providers may differ.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CapabilityRow(label: String, support: CapabilitySupport) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) {},
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Text(
            text = when (support) {
                CapabilitySupport.SUPPORTED -> "✓ Supported"
                CapabilitySupport.UNSUPPORTED -> "Unavailable"
                CapabilitySupport.UNKNOWN -> "Not reported"
            },
            style = MaterialTheme.typography.labelLarge,
            color = if (support == CapabilitySupport.SUPPORTED) {
                MaterialTheme.colorScheme.tertiary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
    }
}
