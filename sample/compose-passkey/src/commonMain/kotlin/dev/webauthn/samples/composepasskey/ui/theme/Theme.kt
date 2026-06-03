@file:Suppress("MagicNumber")

package dev.webauthn.samples.composepasskey.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val Palette: androidx.compose.material3.ColorScheme = lightColorScheme(
    primary = Color(0xFF1E4A68),
    onPrimary = Color(0xFFFFFFFF),
    secondary = Color(0xFF6D8A56),
    onSecondary = Color(0xFFFFFFFF),
    background = Color(0xFFF5F2EB),
    onBackground = Color(0xFF1F2327),
    surface = Color(0xFFFFFCF6),
    onSurface = Color(0xFF1F2327),
    surfaceVariant = Color(0xFFE8E2D8),
    onSurfaceVariant = Color(0xFF4D585F),
    error = Color(0xFFA3333D),
    onError = Color(0xFFFFFFFF),
)

val Typography: Typography = Typography().run {
    copy(
        headlineLarge = headlineLarge.copy(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.SemiBold,
        ),
        headlineMedium = headlineMedium.copy(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.Medium,
        ),
        titleMedium = titleMedium.copy(fontWeight = FontWeight.SemiBold),
        bodySmall = bodySmall.copy(
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
        ),
    )
}
