package dev.webauthn.samples.composepasskey

import dev.webauthn.client.ios.IosPasskeyClient

private val iosPasskeyClient by lazy { IosPasskeyClient() }

internal fun initializeComposePasskeySampleAppKoin() {
    initializeSampleAppKoin(passkeyClient = iosPasskeyClient)
}
