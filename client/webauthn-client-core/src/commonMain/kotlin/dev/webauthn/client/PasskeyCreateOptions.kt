@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

/**
 * Cross-platform hints for a passkey creation ceremony.
 *
 * [Default] preserves the normal user-initiated registration behavior. [Conditional] is intended
 * for automatic passkey upgrades after a successful password or other non-passkey sign-in, when
 * the platform can create a passkey opportunistically without blocking system UI.
 */
public data class PasskeyCreateOptions(
    public val mediation: PasskeyCreateMediation = PasskeyCreateMediation.Default,
) {
    /** Predefined passkey creation option sets. */
    public companion object {
        /** Default explicit create behavior, suitable for user-initiated registration actions. */
        public val Default: PasskeyCreateOptions = PasskeyCreateOptions()

        /** Opportunistic create behavior for automatic passkey upgrades after non-passkey sign-in. */
        public val Conditional: PasskeyCreateOptions = PasskeyCreateOptions(
            mediation = PasskeyCreateMediation.Conditional,
        )
    }
}

/** Platform mediation style requested for a passkey creation ceremony. */
public enum class PasskeyCreateMediation {
    /** Explicit, user-initiated passkey registration. */
    Default,

    /** Conditional passkey creation for automatic passkey upgrades. */
    Conditional,
}
