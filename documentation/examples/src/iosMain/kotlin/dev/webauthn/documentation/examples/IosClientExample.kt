package dev.webauthn.documentation.examples

// docs-region ios-client
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient
import dev.webauthn.client.ios.PasskeyPresentationAnchorProvider

fun iosPasskeyClient(anchorProvider: PasskeyPresentationAnchorProvider): PasskeyClient {
    return IosPasskeyClient(anchorProvider)
}
// docs-endregion ios-client
