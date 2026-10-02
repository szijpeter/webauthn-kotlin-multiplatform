package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cancel
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.mohamedrejeb.calf.ui.progress.AdaptiveCircularProgressIndicator
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.model.StatusTone

@Composable
internal fun StatusCard(status: PasskeyDemoStatus) {
    val colors = MaterialTheme.colorScheme
    val foreground = when (status.tone) {
        StatusTone.ERROR -> colors.error
        StatusTone.SUCCESS -> colors.tertiary
        StatusTone.WORKING -> colors.primary
        StatusTone.WARNING -> colors.onSecondaryContainer
        StatusTone.IDLE -> colors.onSurfaceVariant
    }
    Surface(
        modifier = Modifier.fillMaxWidth().semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite },
        color = colors.surface,
        shape = MaterialTheme.shapes.medium,
    ) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (status.tone == StatusTone.WORKING) {
                AdaptiveCircularProgressIndicator(Modifier.size(22.dp), color = foreground, strokeWidth = 2.dp)
            } else {
                Icon(
                    imageVector = when (status.tone) {
                        StatusTone.SUCCESS -> Icons.Rounded.CheckCircle
                        StatusTone.ERROR -> Icons.Rounded.Cancel
                        StatusTone.WARNING -> Icons.Rounded.Warning
                        else -> Icons.Rounded.Info
                    },
                    contentDescription = null,
                    tint = foreground,
                    modifier = Modifier.size(22.dp),
                )
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(status.headline, style = MaterialTheme.typography.titleSmall)
                status.detail?.let {
                    Text(it, style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
                }
            }
        }
    }
}
