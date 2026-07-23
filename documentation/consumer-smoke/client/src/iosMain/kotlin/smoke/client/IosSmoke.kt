package smoke.client

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient

fun iosSmoke(): PasskeyClient = IosPasskeyClient()
