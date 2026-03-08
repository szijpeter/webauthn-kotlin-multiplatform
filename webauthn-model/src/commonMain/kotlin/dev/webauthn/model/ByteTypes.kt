package dev.webauthn.model

@kotlin.jvm.JvmInline
public value class RpIdHash private constructor(private val value: Base64UrlBytes) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    override fun toString(): String = encoded()

    public companion object {
        private const val LENGTH: Int = 32

        public fun parse(value: String, field: String = "rpIdHash"): ValidationResult<RpIdHash> {
            return when (val parsed = Base64UrlBytes.parse(value, field)) {
                is ValidationResult.Valid -> fromBase64UrlBytes(parsed.value, field)
                is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
            }
        }

        public fun fromBytes(value: ByteArray): RpIdHash {
            require(value.size == LENGTH) { "rpIdHash must be $LENGTH bytes" }
            return RpIdHash(Base64UrlBytes.fromBytes(value))
        }

        public fun parseOrThrow(value: String, field: String = "rpIdHash"): RpIdHash = parse(value, field).getOrThrow()

        internal fun fromBase64UrlBytes(value: Base64UrlBytes, field: String): ValidationResult<RpIdHash> {
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
public value class Aaguid private constructor(private val value: Base64UrlBytes) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    override fun toString(): String = encoded()

    public companion object {
        private const val LENGTH: Int = 16

        public fun parse(value: String, field: String = "aaguid"): ValidationResult<Aaguid> {
            return when (val parsed = Base64UrlBytes.parse(value, field)) {
                is ValidationResult.Valid -> fromBase64UrlBytes(parsed.value, field)
                is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
            }
        }

        public fun fromBytes(value: ByteArray): Aaguid {
            require(value.size == LENGTH) { "aaguid must be $LENGTH bytes" }
            return Aaguid(Base64UrlBytes.fromBytes(value))
        }

        public fun parseOrThrow(value: String, field: String = "aaguid"): Aaguid = parse(value, field).getOrThrow()

        internal fun fromBase64UrlBytes(value: Base64UrlBytes, field: String): ValidationResult<Aaguid> {
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
