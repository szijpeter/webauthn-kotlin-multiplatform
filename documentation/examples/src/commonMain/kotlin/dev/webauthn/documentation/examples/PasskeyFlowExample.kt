@file:Suppress("UndocumentedPublicClass")

package dev.webauthn.documentation.examples

import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.RawRegistrationResponse

// docs-region passkey-flow
data class RegistrationInput(val userName: String)

data class ContinuationToken(val value: String)

data class SignedInAccount(val userName: String)

data class RegistrationStartEnvelope(
    val continuation: ContinuationToken,
    val options: PublicKeyCredentialCreationOptions,
)

interface RegistrationApi {
    suspend fun start(input: RegistrationInput): RegistrationStartEnvelope

    suspend fun finish(
        continuation: ContinuationToken,
        response: RawRegistrationResponse,
    ): SignedInAccount
}

class AppRegistrationBackend(
    private val api: RegistrationApi,
) : RegistrationBackend<RegistrationInput, ContinuationToken, SignedInAccount> {
    override suspend fun start(
        input: RegistrationInput,
    ): CeremonyStart<ContinuationToken, PublicKeyCredentialCreationOptions> {
        val started = api.start(input)
        return CeremonyStart(started.continuation, started.options)
    }

    override suspend fun finish(
        state: ContinuationToken,
        response: RawRegistrationResponse,
    ): SignedInAccount = api.finish(state, response)
}

suspend fun register(
    passkeyClient: PasskeyClient,
    backend: AppRegistrationBackend,
    onPhaseChanged: (PasskeyPhase) -> Unit,
): CeremonyResult<SignedInAccount> = PasskeyFlow(passkeyClient).register(
    input = RegistrationInput("alice"),
    backend = backend,
    onPhaseChanged = onPhaseChanged,
)
// docs-endregion passkey-flow
