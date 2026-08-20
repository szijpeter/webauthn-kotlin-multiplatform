package dev.webauthn.documentation.examples

// docs-region android-json-client
import android.content.Context
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.client.withJsonSupport
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

fun androidJsonClient(context: Context): JsonPasskeyClient {
    val codec = KotlinxWebAuthnJsonCodec()
    val typedClient = AndroidPasskeyClient(context, codec)
    return typedClient.withJsonSupport(codec)
}
// docs-endregion android-json-client
