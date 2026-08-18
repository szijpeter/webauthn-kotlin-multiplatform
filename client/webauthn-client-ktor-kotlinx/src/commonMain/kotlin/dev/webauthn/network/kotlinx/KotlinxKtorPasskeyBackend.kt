package dev.webauthn.network.kotlinx

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.network.KtorPasskeyBackend
import dev.webauthn.network.KtorPasskeyRoutes
import io.ktor.client.HttpClient

/** Default typed backend for the `/webauthn/...` HTTP contract using Kotlinx Serialization. */
public class KotlinxKtorPasskeyBackend(
    httpClient: HttpClient,
    endpointBase: String,
    routes: KtorPasskeyRoutes = KtorPasskeyRoutes(),
) {
    private val backend = KtorPasskeyBackend(
        httpClient = httpClient,
        endpointBase = endpointBase,
        codec = KotlinxKtorPasskeyContractCodec(),
        routes = routes,
    )

    public fun registrationBackend():
        RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> =
        backend.registrationBackend()

    public fun authenticationBackend():
        AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> =
        backend.authenticationBackend()
}
