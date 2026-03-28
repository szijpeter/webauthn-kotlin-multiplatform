package dev.webauthn.runtime

import at.asitplus.nonFatalOrThrow
import kotlinx.coroutines.CancellationException

public fun Throwable.rethrowCancellation() {
    if (this is CancellationException) {
        throw this
    }
}

public fun Throwable.rethrowCancellationOrFatal(): Throwable {
    val nonFatal = nonFatalOrThrow()
    nonFatal.rethrowCancellation()
    return nonFatal
}

@Suppress("TooGenericExceptionCaught")
public suspend fun <T> suspendCatchingNonCancellation(block: suspend () -> T): Result<T> {
    return try {
        Result.success(block())
    } catch (error: Throwable) {
        Result.failure(error.rethrowCancellationOrFatal())
    }
}

/**
 * Coroutine-safe alternative to [runCatching].
 *
 * Like [runCatching], executes [block] and wraps the result in [Result],
 * but rethrows [CancellationException] instead of wrapping it.
 * This preserves structured concurrency cancellation semantics.
 *
 * See [kotlinx.coroutines#1814](https://github.com/Kotlin/kotlinx.coroutines/issues/1814).
 */
@Suppress("TooGenericExceptionCaught")
public suspend inline fun <T> runSuspendCatching(block: () -> T): Result<T> {
    return try {
        Result.success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        Result.failure(e)
    }
}

/**
 * Coroutine-safe alternative to [Result.mapCatching].
 *
 * Like [Result.mapCatching], applies [transform] to a successful result
 * and wraps the outcome in [Result], but rethrows [CancellationException]
 * instead of wrapping it.
 *
 * If the receiver is already a failure, the failure is propagated unchanged.
 *
 * See [kotlinx.coroutines#1814](https://github.com/Kotlin/kotlinx.coroutines/issues/1814).
 */
public suspend inline fun <T, R> Result<T>.mapSuspendCatching(
    transform: (T) -> R,
): Result<R> {
    val value = getOrElse { return Result.failure(it) }
    return runSuspendCatching { transform(value) }
}
