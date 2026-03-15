package dev.webauthn.client

import at.asitplus.catching
import dev.webauthn.model.ValidationResult

internal inline fun <T> fromMapperInvalidOptions(message: String, block: () -> T): T =
    fromMapper(message, block) { composedMessage, error -> IllegalArgumentException(composedMessage, error) }

internal inline fun <T> fromMapperPlatformResponse(message: String, block: () -> T): T =
    fromMapper(message, block) { composedMessage, error -> IllegalStateException(composedMessage, error) }

private inline fun <T, TThrowable : Throwable> fromMapper(
    message: String,
    block: () -> T,
    throwableFactory: (String, Throwable) -> TThrowable,
): T {
    return catching(block)
        .getOrElse { error ->
            val composedMessage = "$message: ${error.message ?: "unknown error"}"
            throw throwableFactory(composedMessage, error)
        }
}

internal fun <T, TThrowable : Throwable> ValidationResult<T>.toValueOrThrow(
    throwableFactory: (String) -> TThrowable,
): T {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> throw throwableFactory(firstValidationErrorMessage())
    }
}

private fun ValidationResult.Invalid.firstValidationErrorMessage(): String {
    val firstError = errors.firstOrNull() ?: return "Unknown validation error"
    return "${firstError.field}: ${firstError.message}"
}
