package dev.webauthn.model

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
@kotlin.jvm.JvmInline
public value class Base64UrlBytes private constructor(private val encodedValue: String) {
    public fun bytes(): ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(encodedValue)

    public fun encoded(): String = encodedValue

    override fun toString(): String = "Base64UrlBytes(${bytes().size} bytes)"

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

            val isDecodable = runCatching {
                // Verify the string can actually be decoded according to Base64Url specs without padding.
                Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(value)
                true
            }.getOrElse {
                false
            }
            if (!isDecodable) {
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
            return Base64UrlBytes(Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(value))
        }

        public fun parseOrThrow(value: String, field: String = "base64url"): Base64UrlBytes {
            return parse(value, field).getOrThrow()
        }
    }
}
