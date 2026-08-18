package dev.webauthn.documentation.examples

// docs-region default-android-client
import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient
import dev.webauthn.json.WebAuthnJsonCodec

fun recommendedAndroidClient(context: Context): PasskeyClient = defaultPasskeyClient(context)

fun customCodecAndroidClient(
    context: Context,
    codec: WebAuthnJsonCodec,
): PasskeyClient = defaultPasskeyClient(context) {
    this.codec = codec
}
// docs-endregion default-android-client
