# webauthn-runtime-core

Audience: module authors who need consistent coroutine-safe failure handling helpers across client/network adapters.

## What it provides

- Coroutine-cancellation helpers (`rethrowCancellation`, `rethrowCancellationOrFatal`).
- `suspendCatchingNonCancellation(...)` wrapper for suspend pipelines (also filters fatal exceptions via `nonFatalOrThrow`).
- `runSuspendCatching(...)` — coroutine-safe drop-in replacement for `runCatching` that rethrows `CancellationException`.
- `Result<T>.mapSuspendCatching(...)` — coroutine-safe drop-in replacement for `Result.mapCatching` that rethrows `CancellationException`.
- A single shared policy implementation so cancellation propagation is consistent across modules.

## When to use

Use this module in internal/runtime-facing adapters where suspend boundaries map platform/network errors to domain results.

**Choosing between utilities:**

| Utility | Use when |
|---|---|
| `runSuspendCatching { }` | Simple coroutine-safe replacement for `runCatching` in suspend contexts |
| `result.mapSuspendCatching { }` | Coroutine-safe replacement for `result.mapCatching` in suspend contexts |
| `suspendCatchingNonCancellation { }` | Need both cancellation rethrow **and** fatal exception filtering (`nonFatalOrThrow`) |

## How to use

<!-- doc-example: id=core-webauthn-runtime-core-readme-kotlin-1; owner=source; verify=unit; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/RuntimeExample.kt#runtime-cancellation -->
```kotlin
import dev.webauthn.runtime.mapSuspendCatching
import dev.webauthn.runtime.runSuspendCatching

suspend fun loadAndTransform(
    fetchData: suspend () -> String,
    transform: suspend (String) -> Int,
    mapFailure: (Throwable) -> Int,
): Int {
    val result = runSuspendCatching { fetchData() }.getOrElse { error ->
        // CancellationException is already rethrown.
        return mapFailure(error)
    }

    return Result.success(result)
        .mapSuspendCatching { transform(it) }
        .getOrThrow()
}
```

## Background

Kotlin's stdlib `runCatching` and `mapCatching` catch **all** `Throwable` including `CancellationException`, which breaks structured concurrency. See [kotlinx.coroutines#1814](https://github.com/Kotlin/kotlinx.coroutines/issues/1814).

This module provides coroutine-safe alternatives that rethrow `CancellationException` before wrapping other exceptions in `Result`.

## How it fits in the system

- Shared by client orchestration and network adapter modules.
- Keeps cancellation policy aligned with steering/docs dependency decisions.

## Limits

- This module does not define domain error models.
- It only standardizes coroutine/failure boundary mechanics.

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta, shared runtime helper module.
