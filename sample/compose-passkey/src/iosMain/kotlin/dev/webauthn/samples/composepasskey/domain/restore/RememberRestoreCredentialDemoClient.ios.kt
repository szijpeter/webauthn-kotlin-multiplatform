package dev.webauthn.samples.composepasskey.domain.restore

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember

@Composable
internal actual fun rememberRestoreCredentialDemoClient(): RestoreCredentialDemoClient {
    return remember { UnsupportedRestoreCredentialDemoClient() }
}
