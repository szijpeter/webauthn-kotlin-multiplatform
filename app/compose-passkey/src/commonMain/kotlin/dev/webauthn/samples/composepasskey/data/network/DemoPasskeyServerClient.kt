package dev.webauthn.samples.composepasskey.data.network

import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload

internal typealias DemoPasskeyServerClient =
    PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>
