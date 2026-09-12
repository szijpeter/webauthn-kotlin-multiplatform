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
    secondary = Color(0xFF7A5500),
    secondaryContainer = Color(0xFFFFF0CA),
    onSecondaryContainer = Color(0xFF7A5500),
    tertiary = Color(0xFF23694D),
    tertiaryContainer = Color(0xFFDDF3E6),
    onTertiaryContainer = Color(0xFF175239),
    background = Color(0xFFF2F2F7),
    onBackground = Color(0xFF1C1C1E),
    surface = Color.White,
    onSurface = Color(0xFF1C1C1E),
    surfaceVariant = Color(0xFFECECEE),
    onSurfaceVariant = Color(0xFF606064),
    surfaceContainer = Color(0xFFECECEE),
    surfaceContainerLow = Color(0xFFF8F8FA),
    surfaceContainerHigh = Color(0xFFE4E4E7),
    outline = Color(0xFF727F94),
    outlineVariant = Color(0xFFDEDEE2),
    error = Color(0xFFAB283B),
    errorContainer = Color(0xFFFFE8EC),
    onErrorContainer = Color(0xFF851C2B),
)

private val DarkPalette = darkColorScheme(
    primary = Color(0xFFAEC6FF),
    onPrimary = Color(0xFF123275),
    primaryContainer = Color(0xFF26334D),
    onPrimaryContainer = Color(0xFFDCE7FF),
    secondary = Color(0xFFF1CD78),
    secondaryContainer = Color(0xFF2C2C2E),
    onSecondaryContainer = Color(0xFFF1CD78),
    tertiary = Color(0xFF98DAB5),
    tertiaryContainer = Color(0xFF183F2F),
    onTertiaryContainer = Color(0xFFBCEFD2),
    background = Color(0xFF000000),
    onBackground = Color(0xFFF2F2F7),
    surface = Color(0xFF1C1C1E),
    onSurface = Color(0xFFF2F2F7),
    surfaceVariant = Color(0xFF2C2C2E),
    onSurfaceVariant = Color(0xFFAEAEB2),
    surfaceContainer = Color(0xFF242426),
    surfaceContainerLow = Color(0xFF121214),
    surfaceContainerHigh = Color(0xFF323234),
    outline = Color(0xFF8E8E93),
    outlineVariant = Color(0xFF38383A),
    error = Color(0xFFFFB4AB),
    errorContainer = Color(0xFF442725),
    onErrorContainer = Color(0xFFFFB4AB),
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
