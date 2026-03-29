@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** Lifecycle phase of a passkey ceremony. */
public enum class PasskeyPhase {
    STARTING,
    PLATFORM_PROMPT,
    FINISHING,
}
