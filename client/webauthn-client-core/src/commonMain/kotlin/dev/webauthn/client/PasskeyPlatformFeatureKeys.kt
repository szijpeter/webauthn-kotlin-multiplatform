@file:Suppress("UndocumentedPublicProperty")

package dev.webauthn.client

/** Stable keys for platform features advertised through [PasskeyCapability.PlatformFeature]. */
public object PasskeyPlatformFeatureKeys {
    /** Cross-platform authenticator / security key support. */
    public const val SecurityKey: String = "securityKey"

    /** Conditional passkey creation for automatic passkey upgrades. */
    public const val ConditionalCreate: String = "conditionalCreate"
}
