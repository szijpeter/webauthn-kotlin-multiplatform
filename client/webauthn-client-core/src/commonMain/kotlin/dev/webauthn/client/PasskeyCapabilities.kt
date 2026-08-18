@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/**
 * Capability support reported by a platform implementation.
 *
 * Missing entries are [CapabilitySupport.UNKNOWN]. This keeps a platform from reporting a
 * capability as unsupported when it cannot determine support reliably at runtime.
 */
public class PasskeyCapabilities(
    support: Map<PasskeyCapability, CapabilitySupport> = emptyMap(),
) {
    /** A defensive snapshot of the support values reported by the platform. */
    public val support: Map<PasskeyCapability, CapabilitySupport> = support.toMap()

    /** Returns the reported support state for [capability]. */
    public fun supportOf(capability: PasskeyCapability): CapabilitySupport =
        support[capability] ?: CapabilitySupport.UNKNOWN

    /** Returns `true` only when [capability] is explicitly reported as supported. */
    public fun supports(capability: PasskeyCapability): Boolean =
        supportOf(capability) == CapabilitySupport.SUPPORTED

    override fun equals(other: Any?): Boolean =
        other is PasskeyCapabilities && support == other.support

    override fun hashCode(): Int = support.hashCode()

    override fun toString(): String = "PasskeyCapabilities(support=$support)"
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
