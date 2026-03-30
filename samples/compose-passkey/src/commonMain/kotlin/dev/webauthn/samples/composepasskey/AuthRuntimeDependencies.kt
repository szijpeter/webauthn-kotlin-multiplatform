package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.staticCompositionLocalOf
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload

internal data class AuthRuntimeDependencies(
    val passkeyClient: PasskeyClient,
    val serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
)

internal val LocalAuthRuntimeDependencies = staticCompositionLocalOf<AuthRuntimeDependencies> {
    error("Auth runtime dependencies were not provided.")
}
