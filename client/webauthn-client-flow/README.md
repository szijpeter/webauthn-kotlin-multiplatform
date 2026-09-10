# webauthn-client-flow

Generic passkey ceremony orchestration over `PasskeyClient` and application-owned backend
contracts, without library-owned product state.

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

<!-- diagram: client-webauthn-client-flow-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-flow-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/client-webauthn-client-flow-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-flow-readme-1-desktop-dark.svg">
  <img alt="client-flow · How it fits in the system. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/client-webauthn-client-flow-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: client-flow · How it fits in the system</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: Application UI and state; webauthn-client-flow; webauthn-client-core; Application backend contract; Android or iOS platform bridge.</p>
<p>1. Application UI and state → webauthn-client-flow.</p>
<p>2. webauthn-client-flow → webauthn-client-core.</p>
<p>3. webauthn-client-flow → Application backend contract.</p>
<p>4. webauthn-client-core → Android or iOS platform bridge.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- A `PasskeyFlow` instance allows one ceremony at a time; concurrent calls are rejected, not queued.
- `onPhaseChanged` is synchronous and application-owned. Do not perform blocking work in it.
- Do not decode or reinterpret opaque continuation state inside the flow layer.
- The flow does not own retries, backend exception mapping, navigation, dialogs, or persisted UI state.

## Status

Beta. The generic contracts and concurrency behavior have common tests; platform runtime coverage
belongs to `webauthn-client-platform` and host applications.
