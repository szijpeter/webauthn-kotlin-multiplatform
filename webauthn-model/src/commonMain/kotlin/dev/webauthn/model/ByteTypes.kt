package dev.webauthn.model

private fun invalidFixedLengthValue(field: String, label: String, length: Int): ValidationResult.Invalid =
    ValidationResult.Invalid(
        listOf(WebAuthnValidationError.InvalidValue(field, "$label must be $length bytes")),
    )

private inline fun <T> parseFixedLengthValue(
    value: String,
    field: String,
    label: String,
    length: Int,
    crossinline constructor: (Base64UrlBytes) -> T,
): ValidationResult<T> =
    when (val parsed = Base64UrlBytes.parse(value, field)) {
        is ValidationResult.Valid -> fromFixedLengthBase64UrlBytes(parsed.value, field, label, length, constructor)
        is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
    }

private inline fun <T> fromFixedLengthBytes(
    value: ByteArray,
    label: String,
    length: Int,
    crossinline constructor: (Base64UrlBytes) -> T,
): T {
    require(value.size == length) { "$label must be $length bytes" }
    return constructor(Base64UrlBytes.fromBytes(value))
}

private inline fun <T> fromFixedLengthBase64UrlBytes(
    value: Base64UrlBytes,
    field: String,
    label: String,
    length: Int,
    crossinline constructor: (Base64UrlBytes) -> T,
): ValidationResult<T> =
    if (value.bytes().size == length) {
        ValidationResult.Valid(constructor(value))
    } else {
        invalidFixedLengthValue(field, label, length)
    }

/** W3C WebAuthn L3: §5.8.1 hash(clientDataJSON) carried in signature verification inputs. */
@kotlin.jvm.JvmInline
public value class ClientDataHash private constructor(private val value: Base64UrlBytes) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    override fun toString(): String = "ClientDataHash($size bytes)"

    /** Constructors and validators for fixed-size clientDataHash values (32 bytes). */
    public companion object {
        private const val LENGTH: Int = 32

        public fun parse(value: String, field: String = "clientDataHash"): ValidationResult<ClientDataHash> =
            parseFixedLengthValue(value, field, "clientDataHash", LENGTH, ::ClientDataHash)

        public fun fromBytes(value: ByteArray): ClientDataHash =
            fromFixedLengthBytes(value, "clientDataHash", LENGTH, ::ClientDataHash)

        public fun parseOrThrow(value: String, field: String = "clientDataHash"): ClientDataHash =
            parse(value, field).getOrThrow()

        internal fun fromBase64UrlBytes(
            value: Base64UrlBytes,
            field: String,
        ): ValidationResult<ClientDataHash> =
            fromFixedLengthBase64UrlBytes(value, field, "clientDataHash", LENGTH, ::ClientDataHash)
    }
}

/** W3C WebAuthn L3: §6.1 rpIdHash field from authenticator data. */
@kotlin.jvm.JvmInline
public value class RpIdHash private constructor(private val value: Base64UrlBytes) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    override fun toString(): String = "RpIdHash($size bytes)"

    /** Constructors and validators for fixed-size rpIdHash values (32 bytes). */
    public companion object {
        private const val LENGTH: Int = 32

        public fun parse(value: String, field: String = "rpIdHash"): ValidationResult<RpIdHash> =
            parseFixedLengthValue(value, field, "rpIdHash", LENGTH, ::RpIdHash)

        public fun fromBytes(value: ByteArray): RpIdHash =
            fromFixedLengthBytes(value, "rpIdHash", LENGTH, ::RpIdHash)

        public fun parseOrThrow(value: String, field: String = "rpIdHash"): RpIdHash = parse(value, field).getOrThrow()

        internal fun fromBase64UrlBytes(value: Base64UrlBytes, field: String): ValidationResult<RpIdHash> =
            fromFixedLengthBase64UrlBytes(value, field, "rpIdHash", LENGTH, ::RpIdHash)
    }
}

/** W3C WebAuthn L3: §6.5 AAGUID value in attested credential data. */
@kotlin.jvm.JvmInline
public value class Aaguid private constructor(private val value: Base64UrlBytes) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    override fun toString(): String = "Aaguid($size bytes)"

    /** Constructors and validators for fixed-size AAGUID values (16 bytes). */
    public companion object {
        private const val LENGTH: Int = 16

        public fun parse(value: String, field: String = "aaguid"): ValidationResult<Aaguid> =
            parseFixedLengthValue(value, field, "aaguid", LENGTH, ::Aaguid)

        public fun fromBytes(value: ByteArray): Aaguid =
            fromFixedLengthBytes(value, "aaguid", LENGTH, ::Aaguid)

        public fun parseOrThrow(value: String, field: String = "aaguid"): Aaguid = parse(value, field).getOrThrow()

        internal fun fromBase64UrlBytes(value: Base64UrlBytes, field: String): ValidationResult<Aaguid> =
            fromFixedLengthBase64UrlBytes(value, field, "aaguid", LENGTH, ::Aaguid)
    }
}

/** W3C WebAuthn L3: §6.5.1 credentialPublicKey (COSE_Key) bytes. */
@kotlin.jvm.JvmInline
public value class CosePublicKey private constructor(private val value: Base64UrlBytes) {
    public val size: Int
        get() = bytes().size

    public fun bytes(): ByteArray = value.bytes()

    public fun encoded(): String = value.encoded()

    public fun contentEquals(other: ByteArray): Boolean = bytes().contentEquals(other)

    override fun toString(): String = "CosePublicKey($size bytes)"

    /** Constructors and validators for credential public key COSE bytes. */
    public companion object {
        public fun parse(value: String, field: String = "cosePublicKey"): ValidationResult<CosePublicKey> {
            return when (val parsed = Base64UrlBytes.parse(value, field)) {
                is ValidationResult.Valid -> ValidationResult.Valid(CosePublicKey(parsed.value))
                is ValidationResult.Invalid -> ValidationResult.Invalid(parsed.errors)
            }
        }

        public fun fromBytes(value: ByteArray): CosePublicKey = CosePublicKey(Base64UrlBytes.fromBytes(value))

        public fun parseOrThrow(value: String, field: String = "cosePublicKey"): CosePublicKey =
            parse(value, field).getOrThrow()

        internal fun fromBase64UrlBytes(value: Base64UrlBytes): CosePublicKey = CosePublicKey(value)
    }
}
