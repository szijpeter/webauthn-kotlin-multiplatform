package smoke.client

import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

fun androidSmoke(context: Context): PasskeyClient = AndroidPasskeyClient(context, KotlinxWebAuthnJsonCodec())
