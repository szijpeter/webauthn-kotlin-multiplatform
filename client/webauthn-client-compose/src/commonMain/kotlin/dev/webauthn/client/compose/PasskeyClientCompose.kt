package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.client.PasskeyFlow

/** Remembers a lifecycle-safe platform [PasskeyClient]. */
@Composable
public expect fun rememberPasskeyClient(): PasskeyClient

/** Remembers the generic, state-free ceremony flow for the provided platform client. */
@Composable
public fun rememberPasskeyFlow(
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
): PasskeyFlow {
    return remember(passkeyClient) { PasskeyFlow(passkeyClient) }
}

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
