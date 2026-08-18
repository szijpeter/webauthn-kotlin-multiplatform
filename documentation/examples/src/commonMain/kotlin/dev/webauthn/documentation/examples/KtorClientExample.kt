@file:Suppress("UndocumentedPublicClass")

package dev.webauthn.documentation.examples

import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.network.KtorPasskeyBackend
import dev.webauthn.network.KtorPasskeyContractCodec
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.network.kotlinx.KotlinxKtorPasskeyBackend
import io.ktor.client.HttpClient

// docs-region neutral-ktor-backend
data class RegistrationCommand(val userName: String)

data class RegistrationContinuation(val token: String)

data class RegisteredAccount(val id: String)

data class AuthenticationCommand(val userName: String?)

data class AuthenticationContinuation(val token: String)

data class AuthenticatedAccount(val id: String)

typealias AppContractCodec = KtorPasskeyContractCodec<
    RegistrationCommand,
    RegistrationContinuation,
    RegisteredAccount,
    AuthenticationCommand,
    AuthenticationContinuation,
    AuthenticatedAccount,
>

fun appKtorBackend(
    httpClient: HttpClient,
    codec: AppContractCodec,
): KtorPasskeyBackend<
    RegistrationCommand,
    RegistrationContinuation,
    RegisteredAccount,
    AuthenticationCommand,
    AuthenticationContinuation,
    AuthenticatedAccount,
> = KtorPasskeyBackend(
    httpClient = httpClient,
    endpointBase = "https://example.com",
    codec = codec,
)
// docs-endregion neutral-ktor-backend

// docs-region kotlinx-ktor-backend
suspend fun authenticateWithDefaultContract(
    httpClient: HttpClient,
    passkeyClient: PasskeyClient,
): CeremonyResult<DefaultPasskeyFinishResult> {
    val backend = KotlinxKtorPasskeyBackend(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
    return PasskeyFlow(passkeyClient).signIn(
        input = AuthenticationStartPayload(
            rpId = "example.com",
            origin = "https://example.com",
            userName = "alice",
        ),
        backend = backend.authenticationBackend(),
    )
}
// docs-endregion kotlinx-ktor-backend
