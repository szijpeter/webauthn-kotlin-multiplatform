@file:Suppress("MagicNumber")

package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.model.StatusTone

@Composable
internal fun StatusPill(tone: StatusTone, text: String) {
    val targetColor = when (tone) {
        StatusTone.IDLE -> Color(0xFFC9D6E0)
        StatusTone.WORKING -> Color(0xFFE4C889)
        StatusTone.SUCCESS -> Color(0xFF97C38A)
        StatusTone.WARNING -> Color(0xFFDCA96F)
        StatusTone.ERROR -> Color(0xFFD2848C)
    }
    val backgroundColor by animateColorAsState(targetValue = targetColor, label = "status-color")

    Surface(
        modifier = Modifier.widthIn(max = 320.dp),
        shape = RoundedCornerShape(999.dp),
        color = backgroundColor,
    ) {
        AnimatedContent(targetState = text, label = "status-text") { label ->
            Text(
                text = label,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF112433),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
