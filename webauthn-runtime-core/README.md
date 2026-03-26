# webauthn-runtime-core

Audience: module authors who need consistent coroutine-safe failure handling helpers across client/network adapters.

## What it provides

- Coroutine-cancellation helpers (`rethrowCancellation`, `rethrowCancellationOrFatal`).
- `suspendCatchingNonCancellation(...)` wrapper for suspend pipelines.
- A single shared policy implementation so cancellation propagation is consistent across modules.

## When to use

Use this module in internal/runtime-facing adapters where suspend boundaries map platform/network errors to domain results.

## How to use

```kotlin
import dev.webauthn.runtime.suspendCatchingNonCancellation

val result = suspendCatchingNonCancellation {
    dependency.call()
}.getOrElse { error ->
    // CancellationException is already rethrown.
    return mapFailure(error)
}
```

## How it fits in the system

- Shared by client orchestration and network adapter modules.
- Keeps cancellation policy aligned with steering/docs dependency decisions.

## Limits

- This module does not define domain error models.
- It only standardizes coroutine/failure boundary mechanics.

## Status

Beta, shared runtime helper module.
