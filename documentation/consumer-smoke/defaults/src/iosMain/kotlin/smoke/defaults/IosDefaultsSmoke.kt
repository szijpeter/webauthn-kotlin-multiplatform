package smoke.defaults

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient

fun defaultIosClient(): PasskeyClient = defaultPasskeyClient()
