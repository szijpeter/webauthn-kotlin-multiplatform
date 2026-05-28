package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyServerClient

/** Remembers a lifecycle-safe platform [PasskeyClient]. */
@Composable
public expect fun rememberPasskeyClient(): PasskeyClient

/** Remembers a [PasskeyController] instance for the provided [serverClient]. */
@Composable
public fun <R, S> rememberPasskeyController(
    serverClient: PasskeyServerClient<R, S>,
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
): PasskeyController<R, S> {
    return remember(passkeyClient, serverClient) {
        PasskeyController(passkeyClient, serverClient)
    }
}
