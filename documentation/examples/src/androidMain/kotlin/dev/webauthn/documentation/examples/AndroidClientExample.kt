package dev.webauthn.documentation.examples

// docs-region android-client
import android.app.Activity
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

fun androidPasskeyClient(activity: Activity): PasskeyClient {
    return AndroidPasskeyClient.forActivity(activity, KotlinxWebAuthnJsonCodec())
}
// docs-endregion android-client
