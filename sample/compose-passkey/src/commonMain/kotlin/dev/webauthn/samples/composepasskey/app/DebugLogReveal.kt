package dev.webauthn.samples.composepasskey.app

import androidx.compose.runtime.staticCompositionLocalOf

internal val LocalShowDebugLogs = staticCompositionLocalOf<() -> Unit> {
    error("Debug log action callback was not provided.")
}
