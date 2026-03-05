package dev.webauthn.samples.composepasskey

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload

private const val DEMO_RP_NAME: String = "WebAuthn Kotlin MPP Sample Backend"

internal fun PasskeyDemoConfig.toRegistrationStartPayload(): RegistrationStartPayload {
    val stableUserHandle = normalizedUserHandle(userHandle)
    return RegistrationStartPayload(
        rpId = rpId,
        rpName = DEMO_RP_NAME,
        origin = origin,
        userName = userName,
        userDisplayName = userName,
        userHandle = stableUserHandle,
    )
}

internal fun PasskeyDemoConfig.toAuthenticationStartPayload(): AuthenticationStartPayload {
    val stableUserHandle = normalizedUserHandle(userHandle)
    return AuthenticationStartPayload(
        rpId = rpId,
        origin = origin,
        userName = userName,
        userHandle = stableUserHandle,
    )
}

private fun normalizedUserHandle(configured: String): String {
    val candidate = configured.trim()
    if (candidate.isEmpty()) {
        return Base64UrlBytes.fromBytes("demo-user".encodeToByteArray()).encoded()
    }
    return when (UserHandle.parse(candidate)) {
        is ValidationResult.Valid -> candidate
        is ValidationResult.Invalid -> Base64UrlBytes.fromBytes(candidate.encodeToByteArray()).encoded()
    }
}
