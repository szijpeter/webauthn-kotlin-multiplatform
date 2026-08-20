package dev.webauthn.documentation.examples

// docs-region network-client
import dev.webauthn.network.kotlinx.KotlinxKtorPasskeyBackend
import io.ktor.client.HttpClient

fun serverBackend(httpClient: HttpClient): KotlinxKtorPasskeyBackend {
    return KotlinxKtorPasskeyBackend(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
}
// docs-endregion network-client
