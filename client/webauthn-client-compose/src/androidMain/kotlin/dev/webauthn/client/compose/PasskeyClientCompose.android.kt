package dev.webauthn.client.compose

import android.app.Application
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.client.android.ForegroundActivityPasskeyPromptContextProvider
import dev.webauthn.client.android.MutablePasskeyPromptContextProvider

/** Remembers an Android-backed [PasskeyClient] that remains valid across activity recreation. */
@Composable
public actual fun rememberPasskeyClient(): PasskeyClient {
    val context = LocalContext.current
    val application = context.applicationContext as? Application
    if (application == null) {
        val provider = remember { MutablePasskeyPromptContextProvider() }
        DisposableEffect(context, provider) {
            provider.update(context)
            onDispose {
                if (provider.currentContextOrNull() === context) {
                    provider.update(null)
                }
            }
        }
        return remember(provider) {
            AndroidPasskeyClient(provider)
        }
    }

    val provider = remember(application, context) {
        ForegroundActivityPasskeyPromptContextProvider.forApplication(
            application = application,
            contextHint = context,
        )
    }
    return remember(provider) {
        AndroidPasskeyClient(provider)
    }
}
