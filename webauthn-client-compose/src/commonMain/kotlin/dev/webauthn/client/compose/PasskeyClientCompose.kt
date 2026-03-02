package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyController

@Composable
public fun rememberPasskeyController(
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
): PasskeyController {
    return remember(passkeyClient) { PasskeyController(passkeyClient) }
}

@Composable
public expect fun rememberPasskeyClient(): PasskeyClient
