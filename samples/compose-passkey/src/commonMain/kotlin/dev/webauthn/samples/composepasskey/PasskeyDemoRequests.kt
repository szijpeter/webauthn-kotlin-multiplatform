package dev.webauthn.samples.composepasskey

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.PrfExtensionInputDto
import dev.webauthn.serialization.PrfValuesDto

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

internal fun PasskeyDemoConfig.toAuthenticationStartPayload(
    prfSalt: Base64UrlBytes? = null,
): AuthenticationStartPayload {
    val stableUserHandle = normalizedUserHandle(userHandle)
    return AuthenticationStartPayload(
        rpId = rpId,
        origin = origin,
        userName = userName,
        userHandle = stableUserHandle,
        extensions = prfSalt?.let { salt ->
            AuthenticationExtensionsClientInputsDto(
                prf = PrfExtensionInputDto(
                    eval = PrfValuesDto(first = salt.encoded()),
                ),
            )
        },
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
