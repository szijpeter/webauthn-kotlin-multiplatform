package dev.webauthn.model

public sealed interface ValidationResult<out T> {
    public data class Valid<T>(public val value: T) : ValidationResult<T>

    public data class Invalid(public val errors: List<WebAuthnValidationError>) : ValidationResult<Nothing>
}

public fun <T> ValidationResult<T>.getOrNull(): T? {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> null
    }
}

public fun <T> ValidationResult<T>.getOrThrow(): T {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> error(errors.joinToString { it.message })
    }
}
