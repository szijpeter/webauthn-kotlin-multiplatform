package dev.webauthn.samples.composepasskey.app.auth

import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyState
import dev.webauthn.samples.composepasskey.domain.passkey.DemoPasskeyAction
import dev.webauthn.samples.composepasskey.domain.passkey.demoTransitionEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

internal class AuthDemoCoordinator(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
) {
    val canRegister: StateFlow<Boolean> field = MutableStateFlow<Boolean>(true)

    private var previousState: DemoCeremonyState = DemoCeremonyState.Idle

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

    fun onAutoCreateClicked() {
        debugLogs.i(
            source = "action",
            message = "Auto Create tapped endpoint=${config.endpointBase} " +
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

    fun onCeremonyStateChanged(current: DemoCeremonyState) {
        demoTransitionEvent(previous = previousState, current = current)?.let { event ->
            when (event.level) {
                DebugLogLevel.DEBUG -> debugLogs.d(source = "flow", message = event.message)
                DebugLogLevel.INFO -> debugLogs.i(source = "flow", message = event.message)
                DebugLogLevel.WARN -> debugLogs.w(source = "flow", message = event.message)
                DebugLogLevel.ERROR -> debugLogs.e(source = "flow", message = event.message)
            }
        }

        when {
            current is DemoCeremonyState.Success && current.action == DemoPasskeyAction.REGISTER -> {
                canRegister.value = false
            }

            current is DemoCeremonyState.Success && current.action == DemoPasskeyAction.SIGN_IN -> {
                sessionStore.signIn(config.userName)
            }
        }

        previousState = current
    }
}
