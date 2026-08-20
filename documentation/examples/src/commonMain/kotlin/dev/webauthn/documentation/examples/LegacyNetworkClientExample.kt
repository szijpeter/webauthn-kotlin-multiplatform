package dev.webauthn.documentation.examples

// docs-region legacy-network-client
import dev.webauthn.network.KtorPasskeyServerClient
import io.ktor.client.HttpClient

fun legacyServerClient(httpClient: HttpClient): KtorPasskeyServerClient {
    return KtorPasskeyServerClient(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
}
// docs-endregion legacy-network-client
