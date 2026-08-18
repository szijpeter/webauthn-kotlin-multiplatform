package dev.webauthn.documentation.examples

// docs-region client-core-flow
import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse

/** Application input for the registration backend in this example. */
data class AccountRegistrationInput(val userId: String)

/** Application input for the authentication backend in this example. */
data class AccountAuthenticationInput(val userId: String)

/** Application-defined registration outcome returned by the backend. */
data class AccountRegistrationOutput(val verified: Boolean)

/** Application-defined authentication outcome returned by the backend. */
data class AccountAuthenticationOutput(val verified: Boolean)

/** Example backend that keeps an opaque registration transaction id. */
class AccountRegistrationBackend : RegistrationBackend<AccountRegistrationInput, String, AccountRegistrationOutput> {
    override suspend fun start(input: AccountRegistrationInput) =
        TODO("Call backend start and return opaque transaction state")

    override suspend fun finish(state: String, response: RawRegistrationResponse): AccountRegistrationOutput =
        TODO("Call backend finish with the raw response and opaque state")
}

/** Example backend that keeps an opaque authentication transaction id. */
class AccountAuthenticationBackend :
    AuthenticationBackend<AccountAuthenticationInput, String, AccountAuthenticationOutput> {
    override suspend fun start(input: AccountAuthenticationInput) =
        TODO("Call backend start and return opaque transaction state")

    override suspend fun finish(state: String, response: RawAuthenticationResponse): AccountAuthenticationOutput =
        TODO("Call backend finish with the raw response and opaque state")
}

/** Runs one authentication ceremony while leaving UI state to the caller. */
suspend fun runSignIn(client: PasskeyClient, userId: String) {
    val result = PasskeyFlow(client).signIn(
        input = AccountAuthenticationInput(userId),
        backend = AccountAuthenticationBackend(),
    )
    when (result) {
        is CeremonyResult.Success -> Unit
        is CeremonyResult.Failure -> Unit
    }
}
// docs-endregion client-core-flow
