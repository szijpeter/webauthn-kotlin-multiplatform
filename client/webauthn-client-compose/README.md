# webauthn-client-compose

Compose helpers for lifecycle-aware platform clients and the generic `PasskeyFlow` API, which owns no product UI state.

## What it provides

- `rememberPasskeyClient()` for a lifecycle-safe Android or iOS platform client.
- `rememberPasskeyFlow(...)` for shared ceremony orchestration with opaque backend state.

The common API exports `webauthn-client-core` and `webauthn-client-flow`. Platform actuals use
`webauthn-client-platform`; Android's no-argument `rememberPasskeyClient()` deliberately selects
`KotlinxWebAuthnJsonCodec`, while iOS uses Authentication Services directly.

## When to use

Use this module when Compose should retain a platform client across recomposition and host lifecycle
changes. The application still owns backend construction, navigation, dialogs, retry policy, and
all visible ceremony state.

## How to use

<!-- doc-example: id=client-webauthn-client-compose-readme-kotlin-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Snippet is intentionally abbreviated for the Compose integration guide -->
```kotlin
val flow = rememberPasskeyFlow()
val state = remember { mutableStateOf<UiState>(UiState.Idle) }

Button(onClick = {
    scope.launch {
        state.value = when (val result = flow.signIn(input, backend.authenticationBackend())) {
            is CeremonyResult.Success -> UiState.Success(result.value)
            is CeremonyResult.Failure -> UiState.Failure(result.error)
        }
    }
}) {
    Text("Sign in")
}
```

Use `webauthn-client-defaults` when you want the recommended platform/Kotlinx composition, or
construct `AndroidPasskeyClient`/`IosPasskeyClient` directly when the application owns codec and
platform configuration.

For a custom Android codec, construct the platform client outside the no-argument Compose helper and
pass it explicitly:

<!-- doc-example: id=client-webauthn-client-compose-readme-kotlin-2; owner=illustrative; verify=illustrative; audience=consumer; reason=Snippet focuses on ownership and omits host-specific dependency injection -->
```kotlin
val passkeyClient = remember { applicationPasskeyClient }
val flow = rememberPasskeyFlow(passkeyClient)
```

## Result and exception behavior

- `CeremonyResult.Failure.Platform` and `CeremonyFailure.AlreadyInProgress` are deliberate outcomes.
- Backend start/finish exceptions, phase-callback exceptions, and unexpected custom-client exceptions
  propagate to the calling coroutine.
- Coroutine cancellation remains control flow. Rethrow it before mapping other exceptions into
  application UI errors.

## Lifecycle and state ownership

- Android resolves the current resumed activity for each prompt so a retained client does not hold a
  destroyed activity after recreation.
- iOS uses the platform client's presentation-anchor policy; construct an anchored client directly
  when the default lookup is not appropriate.
- `rememberPasskeyFlow` remembers by `PasskeyClient` identity. Supplying a new client creates a new
  flow and therefore a new concurrency boundary.
- Do not store screens, messages, or backend exceptions inside `PasskeyFlow`; keep them in the
  application's state holder.

## Status

Beta. Common helper behavior is compiled with the sample, and Android activity recreation is covered
by an instrumentation regression in `webauthn-client-platform`.
