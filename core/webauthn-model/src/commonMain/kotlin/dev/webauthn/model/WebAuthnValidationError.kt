package dev.webauthn.model

/** Structured validation errors used by model parsing and ceremony validation. */
public sealed interface WebAuthnValidationError {
    public val field: String
    public val message: String

    /** Input field value has invalid syntax/shape. */
    public data class InvalidFormat(
        override val field: String,
        override val message: String,
    ) : WebAuthnValidationError

    /** Input field value is syntactically valid but not acceptable. */
    public data class InvalidValue(
        override val field: String,
        override val message: String,
    ) : WebAuthnValidationError

    /** Required input field is absent. */
    public data class MissingValue(
        override val field: String,
        override val message: String,
    ) : WebAuthnValidationError
}
