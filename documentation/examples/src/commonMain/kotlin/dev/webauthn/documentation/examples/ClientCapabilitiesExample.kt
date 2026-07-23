package dev.webauthn.documentation.examples

// docs-region client-capabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.model.WebAuthnExtension

suspend fun inspectCapabilities(client: PasskeyClient) {
    val capabilities = client.capabilities()
    if (capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.Prf))) {
        // Platform supports PRF extension.
    }
    if (capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.LargeBlob))) {
        // Platform supports largeBlob extension.
    }
}
// docs-endregion client-capabilities
