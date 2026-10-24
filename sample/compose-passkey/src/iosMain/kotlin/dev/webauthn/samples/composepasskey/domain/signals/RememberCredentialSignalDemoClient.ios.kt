package dev.webauthn.samples.composepasskey.domain.signals

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember

@Composable
internal actual fun rememberCredentialSignalDemoClient(): CredentialSignalDemoClient {
    return remember { UnsupportedCredentialSignalDemoClient() }
}
