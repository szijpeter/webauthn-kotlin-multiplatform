package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.staticCompositionLocalOf

internal val LocalRevealDebugLogs = staticCompositionLocalOf<() -> Unit> {
    error("Debug log reveal callback was not provided.")
}
