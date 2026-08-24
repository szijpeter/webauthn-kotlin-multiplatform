# Compose lifecycle and UI state

`PasskeyFlow` does not own product state; it keeps only a per-instance concurrency guard. The application owns presentation state, navigation, retry policy, session state, and messages. Compose helpers remember the client and flow; they do not replace a product state model.

## Recommended ownership

| State | Owner | Lifetime |
| --- | --- | --- |
| `PasskeyClient` and `PasskeyFlow` | Stable feature/composition boundary | While its host context remains valid |
| Current `PasskeyPhase` | Screen or view model | One active ceremony |
| Form input and visible error | Product UI state | Screen policy |
| Backend session/account | Application session layer | Product session |
| Raw credential response | Ephemeral flow value | Until finish completes |
| PRF-derived session key | Explicit crypto session | Shortest practical lifetime |

## Concurrency

One flow instance permits one active ceremony. A second call returns `CeremonyFailure.AlreadyInProgress`; it is not queued. Disable registration and sign-in actions while active, and still handle that typed outcome because UI events can race.

## Phase callbacks

The callback reports `STARTING`, `PLATFORM_PROMPT`, and `FINISHING`. It is synchronous and application-owned. Keep it fast, do not perform blocking work, and do not throw unless you intend to abort and handle the exception at your boundary.

## Cancellation and host changes

Let coroutine cancellation propagate. Android Activity recreation, iOS scene changes, navigation, and application backgrounding can invalidate UI hosts. Construct or resolve presentation objects at a lifecycle that matches the platform bridge rather than storing a stale host globally.

## Preview and testing layers

Use fake state for previews, fake `PasskeyClient`/backend implementations for common orchestration tests, platform host tests for mapping and lifecycle behavior, and provider-backed devices for the actual prompt. A preview must not initialize networking, dependency injection, or platform credential APIs.
