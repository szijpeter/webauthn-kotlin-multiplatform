package dev.webauthn.model

/** Typed validation result used by WebAuthn model parsing and ceremony validation flows. */
public sealed interface ValidationResult<out T> {
    /** Successful validation carrying a parsed value. */
    public data class Valid<T>(public val value: T) : ValidationResult<T>

    /** Failed validation carrying one or more domain errors. */
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
