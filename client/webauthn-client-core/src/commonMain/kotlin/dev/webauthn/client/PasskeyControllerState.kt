@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** UI-facing state emitted by [PasskeyController]. */
public sealed interface PasskeyControllerState {
    /** No ceremony is currently in progress. */
    public data object Idle : PasskeyControllerState

    /** A ceremony is running with the provided [action] and [phase]. */
    public data class InProgress(
        public val action: PasskeyAction,
        public val phase: PasskeyPhase,
    ) : PasskeyControllerState

    /** A ceremony completed successfully for [action]. */
    public data class Success(
        public val action: PasskeyAction,
    ) : PasskeyControllerState

    /** A ceremony failed for [action] with [error]. */
    public data class Failure(
        public val action: PasskeyAction,
        public val error: PasskeyClientError,
    ) : PasskeyControllerState
}
