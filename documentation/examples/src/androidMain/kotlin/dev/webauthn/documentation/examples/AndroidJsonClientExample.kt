package dev.webauthn.documentation.examples

// docs-region android-json-client
import android.content.Context
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.client.withJsonSupport

fun androidJsonClient(context: Context): JsonPasskeyClient {
    val typedClient = AndroidPasskeyClient(context)
    return typedClient.withJsonSupport()
}
// docs-endregion android-json-client
