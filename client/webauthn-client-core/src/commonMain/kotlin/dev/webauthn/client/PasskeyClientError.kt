@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** Error surface returned by passkey operations. */
public sealed interface PasskeyClientError {
    public val message: String

    /** The ceremony was aborted because the user dismissed or cancelled the platform prompt. */
    public data class UserCancelled(
        override val message: String = "The user cancelled the passkey prompt",
    ) : PasskeyClientError

    /** The caller supplied invalid inputs, or the platform rejected options before prompting. */
    public data class InvalidOptions(override val message: String) : PasskeyClientError

    /** The ceremony could not be completed because a backend or other transport dependency failed. */
    public data class Transport(override val message: String, public val cause: Throwable? = null) : PasskeyClientError

    /** The platform passkey provider failed for a non-transport reason. */
    public data class Platform(override val message: String, public val cause: Throwable? = null) : PasskeyClientError
}
