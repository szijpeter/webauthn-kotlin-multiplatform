# webauthn-client-flow

Generic, state-free passkey ceremony orchestration over `PasskeyClient` and application-owned
backend contracts.

## What it provides

- `PasskeyFlow` for registration and authentication start/prompt/finish sequencing.
- `RegistrationBackend<Input, State, Output>` and
  `AuthenticationBackend<Input, State, Output>` contracts.
- Exact forwarding of opaque backend `State` from `start` to `finish`.
- Application-defined finish `Output` and observable `PasskeyPhase` changes.
- An explicit `AlreadyInProgress` result when the same flow instance is already running a ceremony.

The module depends on `webauthn-client-core`. It has no Ktor engine, HTTP contract, or JSON
implementation dependency.

## When to use

Use this module when the library should coordinate a platform prompt but your application owns the
backend API and presentation state. Use `PasskeyClient` directly when you only need the OS ceremony,
or add `webauthn-client-ktor` when your backend contract is transported with Ktor.

## How to use

Model backend continuation data as an opaque application type. The flow will return it to the same
backend unchanged after the platform produces a raw credential response.

<!-- doc-example: id=client-webauthn-client-flow-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/PasskeyFlowExample.kt#passkey-flow -->
```kotlin
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
```

Handle `CeremonyResult.Failure.Platform` and `CeremonyFailure.AlreadyInProgress` as deliberate flow
outcomes. Exceptions from backend `start`/`finish`, phase callbacks, and unexpected custom
`PasskeyClient` implementations propagate to the application; coroutine cancellation also remains
control flow. Use `try`/`catch` only where your application can apply a meaningful error policy.

## How it fits in the system

<!-- doc-example: id=client-webauthn-client-flow-readme-mermaid-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart LR
    APP["Application UI and state"] --> FLOW["webauthn-client-flow"]
    FLOW --> CORE["webauthn-client-core"]
    FLOW --> BACKEND["Application backend contract"]
    CORE --> PLATFORM["Android or iOS platform bridge"]
```

## Pitfalls and limits

- A `PasskeyFlow` instance allows one ceremony at a time; concurrent calls are rejected, not queued.
- `onPhaseChanged` is synchronous and application-owned. Do not perform blocking work in it.
- Do not decode or reinterpret opaque continuation state inside the flow layer.
- The flow does not own retries, backend exception mapping, navigation, dialogs, or persisted UI state.

## Status

Beta. The generic contracts and concurrency behavior have common tests; platform runtime coverage
belongs to `webauthn-client-platform` and host applications.
