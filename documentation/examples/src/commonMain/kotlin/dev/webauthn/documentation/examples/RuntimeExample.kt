package dev.webauthn.documentation.examples

// docs-region runtime-cancellation
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
// docs-endregion runtime-cancellation
