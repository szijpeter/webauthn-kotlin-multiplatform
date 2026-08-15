package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.PasskeyServerClient

/** Remembers a lifecycle-safe platform [PasskeyClient]. */
@Composable
public expect fun rememberPasskeyClient(): PasskeyClient

/** Remembers a stateless-UI [PasskeyFlow] for caller-owned Compose state. */
@Composable
public fun rememberPasskeyFlow(
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
): PasskeyFlow {
    return remember(passkeyClient) { PasskeyFlow(passkeyClient) }
}

/**
 * Remembers a legacy state-owning [PasskeyController] for [serverClient].
 *
 * Use [rememberPasskeyFlow] with a typed backend and caller-owned Compose state for new code.
 */
@Deprecated(
    message = "PasskeyController owns UI state. Use rememberPasskeyFlow with a typed backend instead.",
    replaceWith = ReplaceWith("rememberPasskeyFlow(passkeyClient)"),
)
@Composable
public fun <R, S> rememberPasskeyController(
    serverClient: PasskeyServerClient<R, S>,
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
): PasskeyController<R, S> {
    return remember(passkeyClient, serverClient) {
        PasskeyController(passkeyClient, serverClient)
    }
}
