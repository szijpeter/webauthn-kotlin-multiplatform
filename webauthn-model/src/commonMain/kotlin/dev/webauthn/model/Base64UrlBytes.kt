package dev.webauthn.model

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** RFC 4648 §5 base64url bytes without padding, as required by WebAuthn JSON fields. */
@OptIn(ExperimentalEncodingApi::class)
@kotlin.jvm.JvmInline
public value class Base64UrlBytes private constructor(private val encodedValue: String) {
    public fun bytes(): ByteArray = base64UrlNoPadding.decode(encodedValue)

    public fun encoded(): String = encodedValue

    override fun toString(): String = "Base64UrlBytes(${bytes().size} bytes)"

    /** Parsing and construction helpers for RFC 4648 URL-safe base64 values without padding. */
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

            try {
                // Verify the string can actually be decoded according to Base64Url specs without padding.
                base64UrlNoPadding.decode(value)
            } catch (_: IllegalArgumentException) {
                return ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidFormat(
                            field = field,
                            message = "Invalid base64url encoding",
                        ),
                    ),
                )
            }

            return ValidationResult.Valid(Base64UrlBytes(value))
        }

        public fun fromBytes(value: ByteArray): Base64UrlBytes {
            return Base64UrlBytes(base64UrlNoPadding.encode(value))
        }

        public fun parseOrThrow(value: String, field: String = "base64url"): Base64UrlBytes {
            return parse(value, field).getOrThrow()
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
private val base64UrlNoPadding: Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
