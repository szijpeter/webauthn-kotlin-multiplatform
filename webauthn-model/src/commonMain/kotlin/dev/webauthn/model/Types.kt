package dev.webauthn.model

public class RpId private constructor(public val value: String) {
    public companion object {
        private val allowed: Regex = Regex("^[a-z0-9.-]+$")

        public fun parse(value: String): ValidationResult<RpId> {
            val errors = mutableListOf<WebAuthnValidationError>()
            if (value.isBlank()) {
                errors += WebAuthnValidationError.MissingValue("rpId", "RP ID must not be empty")
            }
            if (value.length > 253) {
                errors += WebAuthnValidationError.InvalidValue("rpId", "RP ID exceeds max DNS length")
            }
            if (!allowed.matches(value)) {
                errors += WebAuthnValidationError.InvalidFormat("rpId", "RP ID must be a lowercase host")
            }
            if (value.startsWith('.') || value.endsWith('.')) {
                errors += WebAuthnValidationError.InvalidFormat("rpId", "RP ID must not start or end with a dot")
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

public class Origin private constructor(public val value: String) {
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

public class Challenge private constructor(public val value: Base64UrlBytes) {
    public companion object {
        public fun parse(encoded: String): ValidationResult<Challenge> {
            val baseResult = Base64UrlBytes.parse(encoded, "challenge")
            return when (baseResult) {
                is ValidationResult.Invalid -> baseResult
                is ValidationResult.Valid -> {
                    val size = baseResult.value.bytes().size
                    if (size < 16) {
                        ValidationResult.Invalid(
                            listOf(
                                WebAuthnValidationError.InvalidValue(
                                    field = "challenge",
                                    message = "Challenge must be at least 16 bytes",
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
            require(value.size >= 16) { "Challenge must be at least 16 bytes" }
            return Challenge(Base64UrlBytes.fromBytes(value))
        }

        public fun parseOrThrow(encoded: String): Challenge = parse(encoded).getOrThrow()
    }

    override fun toString(): String = value.toString()
}

public class CredentialId private constructor(public val value: Base64UrlBytes) {
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
}

public class UserHandle private constructor(public val value: Base64UrlBytes) {
    public companion object {
        public fun parse(encoded: String): ValidationResult<UserHandle> {
            return when (val parsed = Base64UrlBytes.parse(encoded, "userHandle")) {
                is ValidationResult.Invalid -> parsed
                is ValidationResult.Valid -> ValidationResult.Valid(UserHandle(parsed.value))
            }
        }

        public fun fromBytes(value: ByteArray): UserHandle = UserHandle(Base64UrlBytes.fromBytes(value))
    }
}

public enum class PublicKeyCredentialType {
    PUBLIC_KEY,
}

public enum class UserVerificationRequirement {
    REQUIRED,
    PREFERRED,
    DISCOURAGED,
}

public enum class AuthenticatorAttachment {
    PLATFORM,
    CROSS_PLATFORM,
}

public enum class ResidentKeyRequirement {
    REQUIRED,
    PREFERRED,
    DISCOURAGED,
}
