package smoke.defaults

import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient

fun defaultAndroidClient(context: Context): PasskeyClient = defaultPasskeyClient(context)
