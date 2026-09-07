@file:Suppress("MagicNumber")

package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

/** Decorative key mark; its adjacent heading supplies the accessible label. */
@Composable
internal fun PasskeyMark() {
    val ink = MaterialTheme.colorScheme.primary
    Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = MaterialTheme.shapes.small) {
        Canvas(Modifier.size(36.dp).padding(8.dp)) {
            val unit = size.width / 24f
            val line = 2.4f * unit
            drawCircle(ink, 5f * unit, Offset(7f * unit, 7f * unit), style = Stroke(line))
            drawLine(ink, Offset(11f * unit, 11f * unit), Offset(21f * unit, 21f * unit), line, StrokeCap.Round)
            drawLine(ink, Offset(17f * unit, 17f * unit), Offset(20f * unit, 14f * unit), line, StrokeCap.Round)
        }
    }
}
