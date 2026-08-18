package dev.webauthn.documentation.examples

// docs-region default-ios-client
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient
import dev.webauthn.client.ios.PasskeyPresentationAnchorProvider

fun recommendedIosClient(): PasskeyClient = defaultPasskeyClient()

fun anchoredIosClient(
    presentationAnchorProvider: PasskeyPresentationAnchorProvider,
): PasskeyClient = defaultPasskeyClient(presentationAnchorProvider)
// docs-endregion default-ios-client
