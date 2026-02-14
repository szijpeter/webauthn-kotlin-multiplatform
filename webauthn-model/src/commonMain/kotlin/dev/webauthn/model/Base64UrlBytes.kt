package dev.webauthn.model

public class Base64UrlBytes private constructor(private val bytes: ByteArray) {
    public fun bytes(): ByteArray = bytes.copyOf()

    public fun encoded(): String = Base64UrlCodec.encode(bytes)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Base64UrlBytes) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    override fun toString(): String {
        return encoded()
    }

    public companion object {
        public fun parse(value: String, field: String = "base64url"): ValidationResult<Base64UrlBytes> {
            if (value.contains('=')) {
                return ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidFormat(
                            field = field,
                            message = "Padding is not allowed in base64url values",
                        ),
                    ),
                )
            }

            val decoded = Base64UrlCodec.decode(value)
                ?: return ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidFormat(
                            field = field,
                            message = "Invalid base64url encoding",
                        ),
                    ),
                )

            return ValidationResult.Valid(Base64UrlBytes(decoded))
        }

        public fun fromBytes(value: ByteArray): Base64UrlBytes = Base64UrlBytes(value.copyOf())

        public fun parseOrThrow(value: String, field: String = "base64url"): Base64UrlBytes {
            return parse(value, field).getOrThrow()
        }
    }
}
