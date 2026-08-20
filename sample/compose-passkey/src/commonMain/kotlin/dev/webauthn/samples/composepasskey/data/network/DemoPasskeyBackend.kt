package dev.webauthn.samples.composepasskey.data.network

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.network.KtorPasskeyRoutes
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.network.kotlinx.KotlinxKtorPasskeyBackend
import dev.webauthn.network.kotlinx.RegistrationStartPayload
import io.ktor.client.HttpClient

internal interface DemoPasskeyBackend {
    val registration: RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult>
    val authentication: AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult>
}

internal class DefaultDemoPasskeyBackend(
    httpClient: HttpClient,
    endpointBase: String,
    routes: KtorPasskeyRoutes = KtorPasskeyRoutes(),
) : DemoPasskeyBackend {
    private val delegate = KotlinxKtorPasskeyBackend(httpClient, endpointBase, routes)

    override val registration: RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> =
        delegate.registrationBackend()

    override val authentication: AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> =
        delegate.authenticationBackend()
}
