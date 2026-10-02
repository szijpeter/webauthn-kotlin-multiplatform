package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.ConfigurationCard
import dev.webauthn.samples.composepasskey.ui.components.DebugLogCard
import dev.webauthn.samples.composepasskey.ui.components.StatusCard
import dev.webauthn.samples.composepasskey.ui.theme.PasskeyDemoTheme

@Preview(name = "Status tones")
@Composable
private fun StatusPreview() {
    PasskeyDemoTheme {
        Surface {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                listOf("auth", "busy", "success", "cancelled", "rejected", "error").forEach {
                    StatusCard(galleryStatus(it))
                }
            }
        }
    }
}

@Preview(name = "Capabilities and configuration")
@Composable
private fun ConfigurationPreview() {
    PasskeyDemoTheme {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            CapabilitiesCard(galleryMainState("unsupported").capabilities)
            ConfigurationCard(GalleryConfig, initiallyExpanded = true)
        }
    }
}

@Preview(name = "Diagnostics · dark")
@Composable
private fun LogsPreview() {
    PasskeyDemoTheme(darkTheme = true) { DebugLogCard(GalleryLogs) }
}
