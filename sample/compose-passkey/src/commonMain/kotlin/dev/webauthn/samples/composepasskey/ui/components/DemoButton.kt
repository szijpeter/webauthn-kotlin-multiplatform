package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.mohamedrejeb.calf.ui.button.AdaptiveButton
import com.mohamedrejeb.calf.ui.button.LiquidGlassButtonColors
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

internal enum class DemoButtonStyle { PRIMARY, TINTED, DESTRUCTIVE }

/** Calf supplies iOS button feedback and rendering; Android retains Material controls. */
@Composable
internal fun DemoButton(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    style: DemoButtonStyle = DemoButtonStyle.TINTED,
) {
    val palette = MaterialTheme.colorScheme
    val (background, foreground) = when (style) {
        DemoButtonStyle.PRIMARY -> palette.primary to palette.onPrimary
        DemoButtonStyle.TINTED -> palette.primaryContainer to palette.onPrimaryContainer
        DemoButtonStyle.DESTRUCTIVE -> palette.errorContainer to palette.onErrorContainer
    }
    AdaptiveButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.heightIn(min = DemoLayout.touchTarget).background(
            color = if (enabled) Color.Transparent else palette.surfaceVariant,
            shape = CircleShape,
        ),
        shape = CircleShape,
        colors = ButtonDefaults.buttonColors(containerColor = background, contentColor = foreground),
        liquidGlassColors = LiquidGlassButtonColors(
            tintColor = Color.Unspecified,
            surfaceColor = background,
            contentColor = foreground,
            disabledContentColor = palette.onSurface,
        ),
    ) {
        ButtonLabel(label, icon)
    }
}

@Composable
internal fun ButtonLabel(label: String, icon: ImageVector) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
        Text(label)
    }
}
