package dev.webauthn.samples.composepasskey

import androidx.compose.ui.window.ComposeUIViewController
import dev.webauthn.samples.composepasskey.app.App
import dev.webauthn.samples.composepasskey.ui.previews.SampleGallery

fun MainViewController() = ComposeUIViewController(
    configure = {
        // Keep the sample app runnable even when host apps use generated plist settings.
        enforceStrictPlistSanityCheck = false
    },
) { App() }

// The iOS host exposes this rendering-only entry point in Debug builds only.
fun GalleryViewController(scenario: String) = ComposeUIViewController(
    configure = { enforceStrictPlistSanityCheck = false },
) { SampleGallery(scenario) }
