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
