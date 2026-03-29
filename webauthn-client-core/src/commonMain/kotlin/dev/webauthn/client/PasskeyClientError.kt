@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** Error surface returned by passkey operations. */
public sealed interface PasskeyClientError {
    public val message: String

    public data class UserCancelled(
        override val message: String = "The user cancelled the passkey prompt",
    ) : PasskeyClientError

    public data class InvalidOptions(override val message: String) : PasskeyClientError

    public data class Transport(override val message: String, public val cause: Throwable? = null) : PasskeyClientError

    public data class Platform(override val message: String, public val cause: Throwable? = null) : PasskeyClientError
}
