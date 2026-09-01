# Ceremony flow for native Swift

`WebAuthnFlow` is an optional, source-only Swift package product that coordinates registration and
authentication as `start -> platform prompt -> finish`. It depends on the base `WebAuthn` product, but the
base product does not depend on it. Applications that want to own orchestration can continue using
`PasskeyClient` directly without adding the flow product.

The flow owns sequencing and one-active-operation enforcement only. It does not select a network stack,
backend schema, serializer, UI model, persistence strategy, retry policy, or application session.

## Backend contracts

Implement `RegistrationBackend` and `AuthenticationBackend` around the application's existing backend
client. Each start method returns `CeremonyStart`, containing the platform options JSON and application-owned
continuation state. The corresponding finish method receives that exact state and the platform response.
Opaque state is never inspected, serialized, copied, or modified by the flow.

<!-- doc-example: id=swift-flow-swift-1; owner=illustrative; verify=illustrative; audience=consumer; reason=BackendClient and account models belong to the adopting application -->
```swift
import WebAuthn
import WebAuthnFlow

@MainActor
struct AppRegistrationBackend: RegistrationBackend {
    let api: BackendClient

    func start(input: AccountRegistration) async throws -> CeremonyStart<String> {
        let started = try await api.startRegistration(input)
        return CeremonyStart(
            state: started.transactionID,
            optionsJSON: started.optionsJSON
        )
    }

    func finish(state: String, responseJSON: Data) async throws -> Account {
        try await api.finishRegistration(
            transactionID: state,
            responseJSON: responseJSON
        )
    }
}
```

The generic input, state, and output types are independent for each backend implementation. The Swift facade
uses UTF-8 JSON `Data` at the platform boundary so generated Kotlin models never enter the application API.

## Running a ceremony

Construct one `PasskeyFlow` for the application feature or view model that owns ceremony presentation. The
flow is `MainActor`-isolated because the underlying platform client presents system UI.

<!-- doc-example: id=swift-flow-swift-2; owner=illustrative; verify=illustrative; audience=consumer; reason=UI state and backend values belong to the adopting application -->
```swift
let flow = PasskeyFlow(client: passkeys)
let result = try await flow.register(
    registration,
    backend: AppRegistrationBackend(api: api),
    onPhaseChanged: { phase in
        viewState.phase = phase
    }
)

switch result {
case let .success(account):
    viewState.account = account
case let .failure(failure):
    viewState.failure = failure
@unknown default:
    viewState.failure = .alreadyInProgress
}
```

For an accepted operation, phase callbacks occur in the fixed order
`starting -> platformPrompt -> finishing`. The finishing phase means the application backend is verifying the
response; it is not itself proof that authentication succeeded. Establish an application session only from
the backend's successful finish output.

## Failure and cancellation policy

`CeremonyResult.failure` is deliberately narrow:

- `.alreadyInProgress` means the same flow instance is already running another ceremony.
- `.platform(PasskeyClientError)` preserves a typed failure produced by `PasskeyClientProtocol` during the
  platform prompt.

Backend start/finish errors and phase-callback errors propagate through Swift `throws`; the generic flow does
not reinterpret application semantics. `CancellationError` also propagates unchanged. The in-progress guard
is released for success, classified failure, thrown error, and cancellation, so a later operation can retry.

Custom `PasskeyClientProtocol` implementations should throw `PasskeyClientError` for platform-client failures
and propagate `CancellationError`. Any other error thrown by a custom client is treated as an implementation
error and propagates to the application.

## Testing

Inject a `PasskeyClientProtocol` fake and backend fixture into `PasskeyFlow`. Package tests cover registration
and authentication output, exact state/response forwarding, phase order, typed platform failure, backend and
callback propagation, concurrent rejection, cancellation, and guard release. The native sample consumes the
flow product through application-owned backend adapters and retains separate tests for its UI state mapping.

Run the complete native validation with:

<!-- doc-example: id=swift-flow-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/swift/ci-check.sh
```

See [the base Swift package guide](README.md), [Swift API parity](API_PARITY.md), and
[the native Swift sample](../sample/swift-passkey/README.md).
