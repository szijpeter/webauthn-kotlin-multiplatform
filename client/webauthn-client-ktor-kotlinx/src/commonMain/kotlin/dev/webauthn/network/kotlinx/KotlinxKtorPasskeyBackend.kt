package dev.webauthn.network.kotlinx

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.KtorPasskeyBackend
import dev.webauthn.network.KtorPasskeyRoutes
import dev.webauthn.network.RegistrationStartPayload
import io.ktor.client.HttpClient

/**
 * Default typed backend for the `/webauthn/…` HTTP contract using Kotlinx Serialization.
 *
 * This is an opt-in composition of [KtorPasskeyBackend] and
 * [KotlinxKtorPasskeyContractCodec].
 */
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

    public fun registrationBackend(): RegistrationBackend<RegistrationStartPayload, Unit, PasskeyFinishResult> =
        backend.registrationBackend()

    public fun authenticationBackend(): AuthenticationBackend<AuthenticationStartPayload, Unit, PasskeyFinishResult> =
        backend.authenticationBackend()
}
