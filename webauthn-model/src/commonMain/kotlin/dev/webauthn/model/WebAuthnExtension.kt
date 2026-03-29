package dev.webauthn.model

/**
 * Represents a standard or proprietary extension defined in the W3C WebAuthn specification
 * (or IANA registry).
 *
 * This provides a single source of truth for protocol extension identifiers,
 * mapping strongly to both client capabilities and execution hooks.
 */
public sealed class WebAuthnExtension(public val identifier: String) {
    /** HMAC Secret Extension. W3C WebAuthn L3: §9.2.1. */
    public data object Prf : WebAuthnExtension("prf")

    /** Large blob storage extension. W3C WebAuthn L3: §9.2.2. */
    public data object LargeBlob : WebAuthnExtension("largeBlob")

    /** Credential Properties Extension. W3C WebAuthn L3: §9.2.3. */
    public data object CredProps : WebAuthnExtension("credProps")

    /** Device Public Key Extension. W3C WebAuthn L3: §9.2.4. */
    public data object DevicePubKey : WebAuthnExtension("devicePubKey")

    /** User Verification Method Extension. W3C WebAuthn L3: §9.2.5. */
    public data object Uvm : WebAuthnExtension("uvm")

    /** AppID Exclude Extension. W3C WebAuthn L3: §9.2.6. */
    public data object AppIdExclude : WebAuthnExtension("appidExclude")

    /** FIDO AppID Extension (U2F Backwards Compatibility). W3C WebAuthn L3: §9.2.7. */
    public data object AppId : WebAuthnExtension("appid")

    /** Fallback for proprietary, draft, or unrecognized extensions not yet modeled in the core. */
    public data class Custom(public val key: String) : WebAuthnExtension(key) {
        init {
            require(key !in STANDARD_IDENTIFIERS) {
                "Use a typed WebAuthnExtension for standard identifier '$key'"
            }
        }
    }

    private companion object {
        val STANDARD_IDENTIFIERS: Set<String> = setOf(
            "prf",
            "largeBlob",
            "credProps",
            "devicePubKey",
            "uvm",
            "appidExclude",
            "appid",
        )
    }
}
