@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/** High-level user action currently being executed by the controller. */
public enum class PasskeyAction {
    REGISTER,
    SIGN_IN,
}
