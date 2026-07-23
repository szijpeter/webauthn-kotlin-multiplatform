package dev.webauthn.documentation.examples

// docs-region android-client
import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient

fun androidPasskeyClient(context: Context): PasskeyClient {
    return AndroidPasskeyClient(context)
}
// docs-endregion android-client
