package dev.webauthn.documentation.examples

// docs-region network-client
import dev.webauthn.network.KtorPasskeyBackend
import dev.webauthn.network.KtorPasskeyContractCodec
import io.ktor.client.HttpClient

fun <RegistrationInput, AuthenticationInput, RegistrationOutput, AuthenticationOutput> serverClient(
    httpClient: HttpClient,
    codec: KtorPasskeyContractCodec<RegistrationInput, AuthenticationInput, RegistrationOutput, AuthenticationOutput>,
): KtorPasskeyBackend<RegistrationInput, AuthenticationInput, RegistrationOutput, AuthenticationOutput> {
    return KtorPasskeyBackend(
        httpClient = httpClient,
        endpointBase = "https://example.com",
        codec = codec,
    )
}
// docs-endregion network-client
