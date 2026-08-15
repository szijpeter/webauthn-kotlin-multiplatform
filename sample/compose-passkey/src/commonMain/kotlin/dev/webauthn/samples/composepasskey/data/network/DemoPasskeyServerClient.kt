package dev.webauthn.samples.composepasskey.data.network

import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.network.kotlinx.KotlinxKtorPasskeyBackend

internal typealias DemoPasskeyServerClient =
    PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>

internal typealias DemoPasskeyBackend = KotlinxKtorPasskeyBackend
