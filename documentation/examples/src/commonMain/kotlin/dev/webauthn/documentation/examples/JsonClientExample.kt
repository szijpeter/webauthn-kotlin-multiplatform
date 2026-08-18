package dev.webauthn.documentation.examples

// docs-region json-client
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.withJsonSupport
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

fun jsonClient(passkeyClient: PasskeyClient): JsonPasskeyClient {
    return passkeyClient.withJsonSupport(KotlinxWebAuthnJsonCodec())
}
// docs-endregion json-client
