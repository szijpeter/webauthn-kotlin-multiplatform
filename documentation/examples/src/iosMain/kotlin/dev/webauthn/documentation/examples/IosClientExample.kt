package dev.webauthn.documentation.examples

// docs-region ios-client
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient

fun iosPasskeyClient(): PasskeyClient {
    return IosPasskeyClient()
}
// docs-endregion ios-client
