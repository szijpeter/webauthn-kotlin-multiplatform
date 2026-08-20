@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** Lifecycle phase emitted by the legacy [PasskeyController]. */
public enum class ControllerPhase {
    STARTING,
    PLATFORM_PROMPT,
    FINISHING,
}
