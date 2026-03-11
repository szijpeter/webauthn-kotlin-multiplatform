package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClient

/** iOS [PasskeyClient] implementation delegated to native AuthenticationServices bridge. */
public class IosPasskeyClient : PasskeyClient by IosPasskeyDelegate()

internal expect class IosPasskeyDelegate() : PasskeyClient
