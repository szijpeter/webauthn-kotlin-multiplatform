package dev.webauthn.model

public sealed interface WebAuthnValidationError {
    public val field: String
    public val message: String

    public data class InvalidFormat(
        override val field: String,
        override val message: String,
    ) : WebAuthnValidationError

    public data class InvalidValue(
        override val field: String,
        override val message: String,
    ) : WebAuthnValidationError

    public data class MissingValue(
        override val field: String,
        override val message: String,
    ) : WebAuthnValidationError
}
