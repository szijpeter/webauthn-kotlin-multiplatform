package dev.webauthn.network

import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import kotlinx.serialization.Serializable

/** Payload for registration-start endpoint requests. */
@Serializable
public data class RegistrationStartPayload(
    public val rpId: String,
    public val rpName: String,
    public val origin: String,
    public val userName: String,
    public val userDisplayName: String,
    public val userHandle: String,
    public val residentKey: String? = null,
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
) {
    override fun toString(): String {
        val extensionsValue = if (extensions == null) "none" else "present"
        val residentKeyValue = residentKey ?: "null"
        return "RegistrationStartPayload(" +
            "rpId=$rpId, rpName=$rpName, origin=$origin, " +
            "userName=<redacted>, userDisplayName=<redacted>, userHandle=<redacted>, " +
            "residentKey=$residentKeyValue, extensions=$extensionsValue)"
    }
}

/** Payload for authentication-start endpoint requests. */
@Serializable
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String? = null,
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
) {
    override fun toString(): String {
        val userNameValue = if (userName == null) "null" else "<redacted>"
        val extensionsValue = if (extensions == null) "none" else "present"
        return "AuthenticationStartPayload(" +
            "rpId=$rpId, origin=$origin, userName=$userNameValue, " +
            "extensions=$extensionsValue)"
    }
}
