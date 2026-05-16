@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** Result returned by backend finish endpoints for passkey ceremonies. */
public sealed interface PasskeyFinishResult {
    /** Ceremony verification succeeded on the backend. */
    public data object Verified : PasskeyFinishResult

    /** Ceremony verification was rejected with an optional explanatory message. */
    public data class Rejected(public val message: String? = null) : PasskeyFinishResult
}
