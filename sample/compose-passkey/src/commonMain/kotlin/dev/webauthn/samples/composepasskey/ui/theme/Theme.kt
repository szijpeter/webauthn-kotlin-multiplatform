@file:Suppress("MagicNumber")

package dev.webauthn.samples.composepasskey.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

private val LightPalette = lightColorScheme(
    primary = Color(0xFF2859C5),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE6EDFF),
    onPrimaryContainer = Color(0xFF173A85),
    secondary = Color(0xFF46607E),
    secondaryContainer = Color(0xFFE9EEF6),
    onSecondaryContainer = Color(0xFF243B58),
    tertiary = Color(0xFF23694D),
    tertiaryContainer = Color(0xFFDDF3E6),
    onTertiaryContainer = Color(0xFF175239),
    background = Color(0xFFF3F5FA),
    onBackground = Color(0xFF172033),
    surface = Color.White,
    onSurface = Color(0xFF172033),
    surfaceVariant = Color(0xFFEBEEF5),
    onSurfaceVariant = Color(0xFF536078),
    surfaceContainer = Color(0xFFEBEEF5),
    surfaceContainerLow = Color(0xFFF8F9FD),
    surfaceContainerHigh = Color(0xFFE4E8F1),
    outline = Color(0xFF727F94),
    outlineVariant = Color(0xFFDCE2ED),
    error = Color(0xFFAB283B),
    errorContainer = Color(0xFFFFE8EC),
    onErrorContainer = Color(0xFF851C2B),
)

private val DarkPalette = darkColorScheme(
    primary = Color(0xFFAEC6FF),
    onPrimary = Color(0xFF123275),
    primaryContainer = Color(0xFF243E70),
    onPrimaryContainer = Color(0xFFDCE7FF),
    secondary = Color(0xFFB7C9E2),
    secondaryContainer = Color(0xFF29384F),
    onSecondaryContainer = Color(0xFFDDE7F7),
    tertiary = Color(0xFF98DAB5),
    tertiaryContainer = Color(0xFF183F2F),
    onTertiaryContainer = Color(0xFFBCEFD2),
    background = Color(0xFF10151F),
    onBackground = Color(0xFFE8EDF7),
    surface = Color(0xFF1B2230),
    onSurface = Color(0xFFE8EDF7),
    surfaceVariant = Color(0xFF293344),
    onSurfaceVariant = Color(0xFFBAC5D8),
    surfaceContainer = Color(0xFF242D3D),
    surfaceContainerLow = Color(0xFF171E2B),
    surfaceContainerHigh = Color(0xFF2E394C),
    outline = Color(0xFF8C9AB0),
    outlineVariant = Color(0xFF364257),
    error = Color(0xFFFFB1BE),
    errorContainer = Color(0xFF542735),
    onErrorContainer = Color(0xFFFFDDE3),
)

private val DemoTypography = Typography().run {
    copy(
        headlineLarge = headlineLarge.copy(fontWeight = FontWeight.Bold),
        headlineMedium = headlineMedium.copy(fontWeight = FontWeight.Bold),
        titleLarge = titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelLarge = labelLarge.copy(fontWeight = FontWeight.SemiBold),
    )
}

internal object DemoLayout {
    val spacing = 16.dp
    val contentPadding = 20.dp
    val maxWidth = 1120.dp
    val wideBreakpoint = 840.dp
    val touchTarget = 48.dp
}

@Composable
fun PasskeyDemoTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkPalette else LightPalette,
        typography = DemoTypography,
        shapes = Shapes(
            small = RoundedCornerShape(12.dp),
            medium = RoundedCornerShape(16.dp),
            large = RoundedCornerShape(24.dp),
        ),
        content = content,
    )
}
