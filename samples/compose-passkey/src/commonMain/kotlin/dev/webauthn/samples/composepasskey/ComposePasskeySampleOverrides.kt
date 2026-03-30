package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload

/**
 * Optional test overrides for the compose sample wiring.
 *
 * Tests can inject deterministic clients before launching the host activity to verify
 * lifecycle behavior (for example, Activity recreation).
 */
object ComposePasskeySampleOverrides {
    var passkeyClientOverride: PasskeyClient? = null

    var serverClientOverride: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>? = null

    fun reset() {
        passkeyClientOverride = null
        serverClientOverride = null
    }
}
