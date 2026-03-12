package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient

/** Remembers an iOS-backed [PasskeyClient] for Compose flows. */
@Composable
public actual fun rememberPasskeyClient(): PasskeyClient {
    return remember { IosPasskeyClient() }
}
