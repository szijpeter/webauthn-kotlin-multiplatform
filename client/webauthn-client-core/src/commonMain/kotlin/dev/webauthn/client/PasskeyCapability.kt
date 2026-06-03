@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.WebAuthnExtension

/**
 * Represents a capability or extension that a passkey client, platform bridge,
 * or authenticator might support.
 *
 * Capabilities are modeled as either a typed W3C WebAuthn [Extension] or a
 * [PlatformFeature] behavior.
 */
public sealed class PasskeyCapability {
    public abstract val key: String

    /** A capability that resolves directly to a specific W3C protocol extension identifier. */
    public data class Extension(
        public val extension: WebAuthnExtension,
    ) : PasskeyCapability() {
        override val key: String = extension.identifier
    }

    /** A capability that represents a literal platform transport or OS feature without a protocol payload. */
    public data class PlatformFeature(
        override val key: String,
    ) : PasskeyCapability()
}
