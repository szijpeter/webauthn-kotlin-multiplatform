package dev.webauthn.samples.composepasskey

import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload

private const val DEMO_RP_NAME: String = "WebAuthn Kotlin MPP Temp Server"

internal fun PasskeyDemoConfig.toRegistrationStartPayload(): RegistrationStartPayload {
    return RegistrationStartPayload(
        rpId = rpId,
        rpName = DEMO_RP_NAME,
        origin = origin,
        userName = userName,
        userDisplayName = userName,
        userHandle = userHandle,
    )
}

internal fun PasskeyDemoConfig.toAuthenticationStartPayload(): AuthenticationStartPayload {
    return AuthenticationStartPayload(
        rpId = rpId,
        origin = origin,
        userName = userName,
        userHandle = userHandle,
    )
}
