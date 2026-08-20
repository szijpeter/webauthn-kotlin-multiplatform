package dev.webauthn.samples.composepasskey

import androidx.compose.ui.window.ComposeUIViewController
import dev.webauthn.samples.composepasskey.app.App
import dev.webauthn.samples.composepasskey.domain.signals.IosBridgeCredentialSignalDemoClient
import dev.webauthn.samples.composepasskey.domain.signals.IosCredentialSignalBridge
import dev.webauthn.samples.composepasskey.domain.signals.UnsupportedCredentialSignalDemoClient

fun MainViewController(
    credentialSignalBridge: IosCredentialSignalBridge? = null,
) = ComposeUIViewController(
    configure = {
        // Keep the sample app runnable even when host apps use generated plist settings.
        enforceStrictPlistSanityCheck = false
    },
) {
    App(
        credentialSignalClient = credentialSignalBridge
            ?.let(::IosBridgeCredentialSignalDemoClient)
            ?: UnsupportedCredentialSignalDemoClient(),
    )
}
