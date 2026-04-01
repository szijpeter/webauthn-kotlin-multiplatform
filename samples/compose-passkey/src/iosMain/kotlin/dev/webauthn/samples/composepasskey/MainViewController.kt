package dev.webauthn.samples.composepasskey

import androidx.compose.ui.window.ComposeUIViewController
import dev.webauthn.samples.composepasskey.app.App

fun MainViewController() = ComposeUIViewController(
    configure = {
        // Keep the sample app runnable even when host apps use generated plist settings.
        enforceStrictPlistSanityCheck = false
    },
) { App() }
