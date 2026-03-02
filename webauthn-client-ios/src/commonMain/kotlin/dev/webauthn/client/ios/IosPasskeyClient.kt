package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClient

public class IosPasskeyClient : PasskeyClient by IosPasskeyDelegate()

internal expect class IosPasskeyDelegate() : PasskeyClient
