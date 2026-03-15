package dev.webauthn.model

/** W3C WebAuthn L3: §4 Terminology and RP ID handling rules used by the ceremonies. */
@kotlin.jvm.JvmInline
public value class RpId private constructor(public val value: String) {
    /** Parsers and constructors for RP ID values validated against host-like constraints. */
    public companion object {
        private const val MAX_DNS_LENGTH = 253
        private const val MAX_LABEL_LENGTH = 63
        private val allowedLabel: Regex = Regex("^[a-z0-9-]+$")

        public fun parse(value: String): ValidationResult<RpId> {
            val errors = mutableListOf<WebAuthnValidationError>()
            if (value.isBlank()) {
                errors += WebAuthnValidationError.MissingValue("rpId", "RP ID must not be empty")
            }
            if (value.length > MAX_DNS_LENGTH) {
                errors += WebAuthnValidationError.InvalidValue("rpId", "RP ID exceeds max DNS length")
            }
            if (value.startsWith('.') || value.endsWith('.')) {
                errors += WebAuthnValidationError.InvalidFormat("rpId", "RP ID must not start or end with a dot")
            }
            for (label in value.split('.')) {
                if (label.isEmpty()) {
                    errors += WebAuthnValidationError.InvalidFormat("rpId", "RP ID must not contain empty labels")
                    continue
                }
                if (label.length > MAX_LABEL_LENGTH) {
                    errors += WebAuthnValidationError.InvalidValue(
                        "rpId",
                        "RP ID labels must be at most $MAX_LABEL_LENGTH characters",
                    )
                }
                if (label.startsWith('-') || label.endsWith('-')) {
                    errors += WebAuthnValidationError.InvalidFormat(
                        "rpId",
                        "RP ID labels must not start or end with a hyphen",
                    )
                }
                if (!allowedLabel.matches(label)) {
                    errors += WebAuthnValidationError.InvalidFormat(
                        "rpId",
                        "RP ID labels must use lowercase letters, digits, or hyphen",
                    )
                }
            }
            if (errors.isNotEmpty()) {
                return ValidationResult.Invalid(errors)
            }
            return ValidationResult.Valid(RpId(value))
        }

        public fun parseOrThrow(value: String): RpId = parse(value).getOrThrow()
    }

    override fun toString(): String = value
}

/** W3C WebAuthn L3: §5.8.1 / §7 origin validation input. */
@kotlin.jvm.JvmInline
public value class Origin private constructor(public val value: String) {
    /** Parsers and constructors for ceremony origin values. */
    public companion object {
        public fun parse(value: String): ValidationResult<Origin> {
            if (!value.startsWith("https://") && !value.startsWith("android:apk-key-hash:")) {
                return ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidFormat(
                            field = "origin",
                            message = "Origin must be https:// or android:apk-key-hash:",
                        ),
                    ),
                )
            }
            return ValidationResult.Valid(Origin(value))
        }

        public fun parseOrThrow(value: String): Origin = parse(value).getOrThrow()
    }

    override fun toString(): String = value
}

/** W3C WebAuthn L3: §13.4.3 challenge requirements (minimum entropy/length). */
@kotlin.jvm.JvmInline
public value class Challenge private constructor(public val value: Base64UrlBytes) {
    /** Parsers and constructors enforcing minimum challenge length requirements. */
    public companion object {
        private const val MIN_BYTES = 16

        public fun parse(encoded: String): ValidationResult<Challenge> {
            val baseResult = Base64UrlBytes.parse(encoded, "challenge")
            return when (baseResult) {
                is ValidationResult.Invalid -> baseResult
                is ValidationResult.Valid -> {
                    val size = baseResult.value.bytes().size
                    if (size < MIN_BYTES) {
                        ValidationResult.Invalid(
                            listOf(
                                WebAuthnValidationError.InvalidValue(
                                    field = "challenge",
                                    message = "Challenge must be at least $MIN_BYTES bytes",
                                ),
                            ),
                        )
                    } else {
                        ValidationResult.Valid(Challenge(baseResult.value))
                    }
                }
            }
        }

        public fun fromBytes(value: ByteArray): Challenge {
            require(value.size >= MIN_BYTES) { "Challenge must be at least $MIN_BYTES bytes" }
            return Challenge(Base64UrlBytes.fromBytes(value))
        }

        public fun parseOrThrow(encoded: String): Challenge = parse(encoded).getOrThrow()
    }

    override fun toString(): String = "Challenge(${value.bytes().size} bytes)"
}

/** W3C WebAuthn L3: §5.1 credential identifier type. */
@kotlin.jvm.JvmInline
public value class CredentialId private constructor(public val value: Base64UrlBytes) {
    /** Parsers and constructors for credential identifier values. */
    public companion object {
        public fun parse(encoded: String): ValidationResult<CredentialId> {
            return when (val parsed = Base64UrlBytes.parse(encoded, "credentialId")) {
                is ValidationResult.Invalid -> parsed
                is ValidationResult.Valid -> ValidationResult.Valid(CredentialId(parsed.value))
            }
        }

        public fun fromBytes(value: ByteArray): CredentialId = CredentialId(Base64UrlBytes.fromBytes(value))

        public fun parseOrThrow(encoded: String): CredentialId = parse(encoded).getOrThrow()
    }

    override fun toString(): String = "CredentialId(${value.bytes().size} bytes)"
}

/** W3C WebAuthn L3: §5.4.3 user handle type. */
@kotlin.jvm.JvmInline
public value class UserHandle private constructor(public val value: Base64UrlBytes) {
    /** Parsers and constructors for user handle values. */
    public companion object {
        public fun parse(encoded: String): ValidationResult<UserHandle> {
            return when (val parsed = Base64UrlBytes.parse(encoded, "userHandle")) {
                is ValidationResult.Invalid -> parsed
                is ValidationResult.Valid -> ValidationResult.Valid(UserHandle(parsed.value))
            }
        }

        public fun fromBytes(value: ByteArray): UserHandle = UserHandle(Base64UrlBytes.fromBytes(value))

        public fun parseOrThrow(encoded: String): UserHandle = parse(encoded).getOrThrow()
    }

    override fun toString(): String = "UserHandle(${value.bytes().size} bytes)"
}

/** W3C WebAuthn L3: §5.8 PublicKeyCredential.type values. */
public enum class PublicKeyCredentialType {
    PUBLIC_KEY,
}

/** W3C WebAuthn L3: §5.4.6 UserVerificationRequirement enumeration. */
public enum class UserVerificationRequirement {
    REQUIRED,
    PREFERRED,
    DISCOURAGED,
}

/** W3C WebAuthn L3: §5.4.5 AuthenticatorAttachment enumeration. */
public enum class AuthenticatorAttachment {
    PLATFORM,
    CROSS_PLATFORM,
}

/** W3C WebAuthn L3: §5.8.4 AuthenticatorTransport enumeration. */
public enum class AuthenticatorTransport {
    USB,
    NFC,
    BLE,
    SMART_CARD,
    HYBRID,
    INTERNAL,
}

/** W3C WebAuthn L3: §5.4.7 AttestationConveyancePreference enumeration. */
public enum class AttestationConveyancePreference {
    NONE,
    INDIRECT,
    DIRECT,
    ENTERPRISE,
}

/** W3C WebAuthn L3: §5.4.6 ResidentKeyRequirement enumeration. */
public enum class ResidentKeyRequirement {
    REQUIRED,
    PREFERRED,
    DISCOURAGED,
}
