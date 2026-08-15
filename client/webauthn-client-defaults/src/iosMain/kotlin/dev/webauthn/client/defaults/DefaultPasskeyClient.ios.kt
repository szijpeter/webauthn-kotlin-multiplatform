package dev.webauthn.client.defaults

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient
import dev.webauthn.client.ios.PasskeyPresentationAnchorProvider

/** Creates the recommended iOS platform client with the system presentation-anchor behavior. */
public fun defaultPasskeyClient(): PasskeyClient = IosPasskeyClient()

/** Creates the recommended iOS platform client with application-owned presentation anchoring. */
public fun defaultPasskeyClient(
    presentationAnchorProvider: PasskeyPresentationAnchorProvider,
): PasskeyClient = IosPasskeyClient(presentationAnchorProvider)
