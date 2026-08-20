package dev.webauthn.client.platform

internal class PasskeyCodecException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

internal class InvalidPlatformResponseException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
