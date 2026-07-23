package smoke.client

import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient

fun androidSmoke(context: Context): PasskeyClient = AndroidPasskeyClient(context)
