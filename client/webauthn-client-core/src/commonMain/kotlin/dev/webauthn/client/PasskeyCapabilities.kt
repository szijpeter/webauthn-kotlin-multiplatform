@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/**
 * Capability support reported by a platform implementation.
 *
 * Missing entries are [CapabilitySupport.UNKNOWN]. This keeps a platform from reporting a
 * capability as unsupported when it cannot determine support reliably at runtime.
 */
public data class PasskeyCapabilities(
    public val support: Map<PasskeyCapability, CapabilitySupport> = emptyMap(),
) {
    private val supportByCapability: Map<PasskeyCapability, CapabilitySupport> = support.toMap()

    /** Returns the reported support state for [capability]. */
    public fun supportOf(capability: PasskeyCapability): CapabilitySupport =
        supportByCapability[capability] ?: CapabilitySupport.UNKNOWN

    /** Returns `true` only when [capability] is explicitly reported as supported. */
    public fun supports(capability: PasskeyCapability): Boolean =
        supportOf(capability) == CapabilitySupport.SUPPORTED
}

/** The confidence with which a platform can report support for a capability. */
public enum class CapabilitySupport {
    /** The platform integration can use the capability. */
    SUPPORTED,

    /** The platform integration cannot use the capability. */
    UNSUPPORTED,

    /** The platform integration cannot determine support reliably. */
    UNKNOWN,
}
