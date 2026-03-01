package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient

@Composable
public actual fun rememberPasskeyClient(): PasskeyClient {
    return remember { IosPasskeyClient() }
}
