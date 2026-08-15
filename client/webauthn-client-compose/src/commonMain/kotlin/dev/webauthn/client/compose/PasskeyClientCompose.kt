package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFlow

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
