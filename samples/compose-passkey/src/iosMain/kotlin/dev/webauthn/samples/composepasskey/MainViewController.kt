package dev.webauthn.samples.composepasskey

import androidx.compose.ui.window.ComposeUIViewController
import platform.UIKit.UIViewController

fun MainViewController(): UIViewController {
    initializeComposePasskeySampleAppKoin()
    return ComposeUIViewController(
        configure = {
            // Keep the sample app runnable even when host apps use generated plist settings.
            enforceStrictPlistSanityCheck = false
        },
    ) { App() }
}
