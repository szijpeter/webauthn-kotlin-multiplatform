@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/**
 * Capability hints surfaced by platform implementations.
 *
 * Use [supports] with a [PasskeyCapability] object to query a specific capability.
 * Extensions and platform bridges can advertise capabilities dynamically without modifying
 * this class.
 */
public data class PasskeyCapabilities(
    public val supported: Set<PasskeyCapability> = emptySet(),
    public val platformVersionHints: List<String> = emptyList(),
) {
    private val supportedByKey: Map<String, PasskeyCapability> =
        supported.associateBy(PasskeyCapability::key)
            .also { capabilitiesByKey ->
                require(capabilitiesByKey.size == supported.size) {
                    "Duplicate capability keys are not allowed"
                }
            }

    /** Returns `true` if the given [capability] is supported. */
    public fun supports(capability: PasskeyCapability): Boolean = supportedByKey[capability.key] == capability

    /** Returns `true` if the given capability [key] is supported. */
    public fun supports(key: String): Boolean = key in supportedByKey
}
