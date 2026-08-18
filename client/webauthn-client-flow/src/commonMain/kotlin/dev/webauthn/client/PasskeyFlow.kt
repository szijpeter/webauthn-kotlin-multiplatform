@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import kotlinx.coroutines.sync.Mutex

/** Server-owned continuation state and options returned when a ceremony starts. */
public data class CeremonyStart<State, Options>(
    public val state: State,
    public val options: Options,
)

/** Backend contract for a registration ceremony with opaque state and application output. */
public interface RegistrationBackend<Input, State, Output> {
    public suspend fun start(input: Input): CeremonyStart<State, PublicKeyCredentialCreationOptions>

    public suspend fun finish(state: State, response: RawRegistrationResponse): Output
}

/** Backend contract for an authentication ceremony with opaque state and application output. */
public interface AuthenticationBackend<Input, State, Output> {
    public suspend fun start(input: Input): CeremonyStart<State, PublicKeyCredentialRequestOptions>

    public suspend fun finish(state: State, response: RawAuthenticationResponse): Output
}

/** Completion value or deliberately classified platform/concurrency failure. */
public sealed interface CeremonyResult<out Output> {
    public data class Success<Output>(public val value: Output) : CeremonyResult<Output>

    public data class Failure(public val error: CeremonyFailure) : CeremonyResult<Nothing>
}

/** Failures that the generic flow can classify without owning application/backend semantics. */
public sealed interface CeremonyFailure {
    /** Another ceremony is already using this flow instance. */
    public data object AlreadyInProgress : CeremonyFailure

    /** The platform client returned a deliberate passkey failure. */
    public data class Platform(public val error: PasskeyClientError) : CeremonyFailure
}

/**
 * Stateless ceremony orchestration that carries opaque backend state from start through finish.
 * Backend and callback exceptions deliberately propagate to the application.
 */
public class PasskeyFlow(
    private val passkeyClient: PasskeyClient,
) {
    private val ceremonyMutex = Mutex()

    public suspend fun <Input, State, Output> register(
        input: Input,
        backend: RegistrationBackend<Input, State, Output>,
        onPhaseChanged: (PasskeyPhase) -> Unit = {},
    ): CeremonyResult<Output> {
        return runCeremony(
            start = { backend.start(input) },
            prompt = passkeyClient::createCredential,
            finish = backend::finish,
            onPhaseChanged = onPhaseChanged,
        )
    }

    public suspend fun <Input, State, Output> signIn(
        input: Input,
        backend: AuthenticationBackend<Input, State, Output>,
        onPhaseChanged: (PasskeyPhase) -> Unit = {},
    ): CeremonyResult<Output> {
        return runCeremony(
            start = { backend.start(input) },
            prompt = passkeyClient::getAssertion,
            finish = backend::finish,
            onPhaseChanged = onPhaseChanged,
        )
    }

    private suspend fun <State, Options, Response, Output> runCeremony(
        start: suspend () -> CeremonyStart<State, Options>,
        prompt: suspend (Options) -> PasskeyResult<Response>,
        finish: suspend (State, Response) -> Output,
        onPhaseChanged: (PasskeyPhase) -> Unit,
    ): CeremonyResult<Output> {
        if (!ceremonyMutex.tryLock()) {
            return CeremonyResult.Failure(CeremonyFailure.AlreadyInProgress)
        }
        try {
            onPhaseChanged(PasskeyPhase.STARTING)
            val ceremonyStart = start()
            onPhaseChanged(PasskeyPhase.PLATFORM_PROMPT)
            val response = when (val result = prompt(ceremonyStart.options)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> return CeremonyResult.Failure(CeremonyFailure.Platform(result.error))
            }
            onPhaseChanged(PasskeyPhase.FINISHING)
            return CeremonyResult.Success(finish(ceremonyStart.state, response))
        } finally {
            ceremonyMutex.unlock()
        }
    }
}
