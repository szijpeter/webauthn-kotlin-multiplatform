package dev.webauthn.samples.composepasskey.app.auth

import dev.webauthn.client.PasskeyAction
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoCeremonyState
import dev.webauthn.samples.composepasskey.domain.passkey.ceremonyTransitionEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

internal class AuthDemoCoordinator(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
) {
    val canRegister: StateFlow<Boolean> field = MutableStateFlow<Boolean>(true)

    private var previousCeremonyState: PasskeyDemoCeremonyState = PasskeyDemoCeremonyState.Idle

    init {
        debugLogs.i(
            source = "app",
            message = "Config endpoint=${config.endpointBase} rpId=${config.rpId} " +
                "origin=${config.origin}",
        )
    }

    fun onRegisterClicked() {
        debugLogs.i(
            source = "action",
            message = "Register tapped endpoint=${config.endpointBase} " +
                "rpId=${config.rpId}",
        )
    }

    fun onSignInClicked() {
        debugLogs.i(
            source = "action",
            message = "Sign In tapped endpoint=${config.endpointBase} " +
                "rpId=${config.rpId}",
        )
    }

    fun onCeremonyStateChanged(current: PasskeyDemoCeremonyState) {
        ceremonyTransitionEvent(previous = previousCeremonyState, current = current)?.let { event ->
            when (event.level) {
                DebugLogLevel.DEBUG -> debugLogs.d(source = "ceremony", message = event.message)
                DebugLogLevel.INFO -> debugLogs.i(source = "ceremony", message = event.message)
                DebugLogLevel.WARN -> debugLogs.w(source = "ceremony", message = event.message)
                DebugLogLevel.ERROR -> debugLogs.e(source = "ceremony", message = event.message)
            }
        }

        when {
            current is PasskeyDemoCeremonyState.Success && current.action == PasskeyAction.REGISTER -> {
                canRegister.value = false
            }

            current is PasskeyDemoCeremonyState.Success && current.action == PasskeyAction.SIGN_IN -> {
                sessionStore.signIn(config.userName)
            }
        }

        previousCeremonyState = current
    }
}
