package dev.webauthn.documentation.examples

// docs-region network-client
import dev.webauthn.network.KtorPasskeyServerClient
import io.ktor.client.HttpClient

fun serverClient(httpClient: HttpClient): KtorPasskeyServerClient {
    return KtorPasskeyServerClient(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
}
// docs-endregion network-client
