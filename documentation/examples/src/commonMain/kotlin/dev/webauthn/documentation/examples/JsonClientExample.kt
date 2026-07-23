package dev.webauthn.documentation.examples

// docs-region json-client
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.withJsonSupport

fun jsonClient(passkeyClient: PasskeyClient): JsonPasskeyClient {
    return passkeyClient.withJsonSupport(KotlinxPasskeyJsonMapper())
}
// docs-endregion json-client
