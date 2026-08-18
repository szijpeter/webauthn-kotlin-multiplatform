@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.WebAuthnExtension

/**
 * Represents a capability or extension that a passkey client, platform bridge,
 * or authenticator might support.
 *
 * Capabilities are modeled as either a typed W3C WebAuthn [Extension] or a
 * typed [Platform] behavior.
 */
public sealed interface PasskeyCapability {
    /** A capability that resolves directly to a specific W3C protocol extension identifier. */
    public data class Extension(
        public val extension: WebAuthnExtension,
    ) : PasskeyCapability

    /** A capability supplied by the operating-system platform integration. */
    public data class Platform(
        public val feature: PlatformCapability,
    ) : PasskeyCapability
}

/**
 * A typed platform behavior that can be reported by [PasskeyCapability.Platform].
 *
 * Use [Custom] only for a stable, documented platform feature that does not yet have a
 * dedicated type.
 */
public sealed interface PlatformCapability {
    /** Support for cross-platform security-key ceremonies. */
    public data object SecurityKey : PlatformCapability

    /** A stable, implementation-defined platform behavior. */
    public data class Custom(
        public val id: String,
    ) : PlatformCapability {
        init {
            require(id.isNotBlank()) {
                "Custom platform capability ID must not be blank"
            }
        }
    }
}
