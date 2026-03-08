package dev.webauthn.model

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
@kotlin.jvm.JvmInline
public value class ImmutableBytes private constructor(private val encodedValue: String) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(encodedValue)

    public fun encoded(): String = encodedValue

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    public fun isEmpty(): Boolean = encodedValue.isEmpty()

    public fun isNotEmpty(): Boolean = encodedValue.isNotEmpty()

    override fun toString(): String = encoded()

    public companion object {
        public fun parse(value: String, field: String = "bytes"): ValidationResult<ImmutableBytes> {
            return when (val parsed = Base64UrlBytes.parse(value, field)) {
                is ValidationResult.Valid -> ValidationResult.Valid(ImmutableBytes(parsed.value.encoded()))
                is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
            }
        }

        public fun fromBytes(value: ByteArray): ImmutableBytes = ImmutableBytes(
            Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(value),
        )

        public fun parseOrThrow(value: String, field: String = "bytes"): ImmutableBytes = parse(value, field).getOrThrow()
    }
}

@kotlin.jvm.JvmInline
public value class RpIdHash private constructor(private val value: ImmutableBytes) {
    public val size: Int
        get() = value.size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = value.contentEquals(other)

    override fun toString(): String = encoded()

    public companion object {
        private const val LENGTH: Int = 32

        public fun parse(value: String, field: String = "rpIdHash"): ValidationResult<RpIdHash> {
            return when (val parsed = ImmutableBytes.parse(value, field)) {
                is ValidationResult.Valid -> fromImmutableBytes(parsed.value, field)
                is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
            }
        }

        public fun fromBytes(value: ByteArray): RpIdHash {
            require(value.size == LENGTH) { "rpIdHash must be $LENGTH bytes" }
            return RpIdHash(ImmutableBytes.fromBytes(value))
        }

        public fun parseOrThrow(value: String, field: String = "rpIdHash"): RpIdHash = parse(value, field).getOrThrow()

        internal fun fromImmutableBytes(value: ImmutableBytes, field: String): ValidationResult<RpIdHash> {
            return if (value.bytes().size == LENGTH) {
                ValidationResult.Valid(RpIdHash(value))
            } else {
                ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue(field, "rpIdHash must be $LENGTH bytes")),
                )
            }
        }
    }
}

@kotlin.jvm.JvmInline
public value class Aaguid private constructor(private val value: ImmutableBytes) {
    public val size: Int
        get() = value.size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = value.contentEquals(other)

    override fun toString(): String = encoded()

    public companion object {
        private const val LENGTH: Int = 16

        public fun parse(value: String, field: String = "aaguid"): ValidationResult<Aaguid> {
            return when (val parsed = ImmutableBytes.parse(value, field)) {
                is ValidationResult.Valid -> fromImmutableBytes(parsed.value, field)
                is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
            }
        }

        public fun fromBytes(value: ByteArray): Aaguid {
            require(value.size == LENGTH) { "aaguid must be $LENGTH bytes" }
            return Aaguid(ImmutableBytes.fromBytes(value))
        }

        public fun parseOrThrow(value: String, field: String = "aaguid"): Aaguid = parse(value, field).getOrThrow()

        internal fun fromImmutableBytes(value: ImmutableBytes, field: String): ValidationResult<Aaguid> {
            return if (value.bytes().size == LENGTH) {
                ValidationResult.Valid(Aaguid(value))
            } else {
                ValidationResult.Invalid(
                    listOf(WebAuthnValidationError.InvalidValue(field, "aaguid must be $LENGTH bytes")),
                )
            }
        }
    }
}
