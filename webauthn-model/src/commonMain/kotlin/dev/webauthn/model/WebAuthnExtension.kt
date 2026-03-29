package dev.webauthn.model

/**
 * Represents a standard or proprietary extension defined in the W3C WebAuthn specification
 * (or IANA registry).
 *
 * This provides a single source of truth for protocol extension identifiers,
 * mapping strongly to both client capabilities and execution hooks.
 */
public sealed interface WebAuthnExtension {
    public val identifier: String

    /** Standardized W3C WebAuthn extension identifiers. */
    public enum class Standard(
        override val identifier: String,
    ) : WebAuthnExtension {
        /** HMAC Secret Extension. W3C WebAuthn L3: §9.2.1. */
        Prf("prf"),

        /** Large blob storage extension. W3C WebAuthn L3: §9.2.2. */
        LargeBlob("largeBlob"),

        /** Credential Properties Extension. W3C WebAuthn L3: §9.2.3. */
        CredProps("credProps"),

        /** Device Public Key Extension. W3C WebAuthn L3: §9.2.4. */
        DevicePubKey("devicePubKey"),

        /** User Verification Method Extension. W3C WebAuthn L3: §9.2.5. */
        Uvm("uvm"),

        /** AppID Exclude Extension. W3C WebAuthn L3: §9.2.6. */
        AppIdExclude("appidExclude"),

        /** FIDO AppID Extension (U2F Backwards Compatibility). W3C WebAuthn L3: §9.2.7. */
        AppId("appid"),
    }

    /** Fallback for proprietary, draft, or unrecognized extensions not yet modeled in the core. */
    public data class Custom(public val key: String) : WebAuthnExtension {
        init {
            require(standardByIdentifier(key) == null) {
                "Use a typed WebAuthnExtension for standard identifier '$key'"
            }
        }

        override val identifier: String = key
    }

    /** Companion utilities for standard extension aliases and identifier-based lookup. */
    public companion object {
        /** Convenience aliases preserving `WebAuthnExtension.Prf`-style call sites. */
        public val Prf: Standard = Standard.Prf
        public val LargeBlob: Standard = Standard.LargeBlob
        public val CredProps: Standard = Standard.CredProps
        public val DevicePubKey: Standard = Standard.DevicePubKey
        public val Uvm: Standard = Standard.Uvm
        public val AppIdExclude: Standard = Standard.AppIdExclude
        public val AppId: Standard = Standard.AppId

        /** Iterable set of all standardized extension identifiers. */
        public val standardExtensions: Set<Standard> = Standard.entries.toSet()

        private val standardByIdentifierIndex: Map<String, Standard> =
            Standard.entries.associateBy(Standard::identifier)

        public fun standardByIdentifier(identifier: String): Standard? = standardByIdentifierIndex[identifier]
    }
}
