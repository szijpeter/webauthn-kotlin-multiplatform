package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.staticCompositionLocalOf

internal val LocalShowDebugLogs = staticCompositionLocalOf<() -> Unit> {
    error("Debug log action callback was not provided.")
}
