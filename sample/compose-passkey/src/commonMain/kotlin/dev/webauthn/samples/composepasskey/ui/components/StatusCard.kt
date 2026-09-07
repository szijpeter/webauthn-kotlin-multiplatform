package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.model.StatusTone

@Composable
internal fun StatusCard(status: PasskeyDemoStatus) {
    val colors = MaterialTheme.colorScheme
    val (background, foreground) = when (status.tone) {
        StatusTone.ERROR -> colors.errorContainer to colors.onErrorContainer
        StatusTone.SUCCESS -> colors.tertiaryContainer to colors.onTertiaryContainer
        StatusTone.WORKING -> colors.primaryContainer to colors.onPrimaryContainer
        StatusTone.IDLE, StatusTone.WARNING -> colors.secondaryContainer to colors.onSecondaryContainer
    }
    Surface(
        modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite },
        color = background,
        contentColor = foreground,
        shape = MaterialTheme.shapes.medium,
    ) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (status.tone == StatusTone.WORKING) {
                CircularProgressIndicator(Modifier.size(20.dp), color = foreground, strokeWidth = 2.dp)
            } else {
                Text(
                    text = when (status.tone) {
                        StatusTone.SUCCESS -> "✓"
                        StatusTone.ERROR, StatusTone.WARNING -> "!"
                        else -> "i"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.clearAndSetSemantics {},
                )
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(status.headline, style = MaterialTheme.typography.titleSmall)
                status.detail?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
        }
    }
}
