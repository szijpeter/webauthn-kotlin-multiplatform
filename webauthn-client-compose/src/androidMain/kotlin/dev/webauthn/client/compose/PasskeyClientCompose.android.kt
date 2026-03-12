package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient

/** Remembers an Android-backed [PasskeyClient] bound to the current Compose context. */
@Composable
public actual fun rememberPasskeyClient(): PasskeyClient {
    val context = LocalContext.current
    return remember(context) { AndroidPasskeyClient(context) }
}
