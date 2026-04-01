package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

internal class AuthDemoCoordinator(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
) {
    private val canRegisterStateFlow = MutableStateFlow(true)
    val canRegister: StateFlow<Boolean> = canRegisterStateFlow.asStateFlow()

    private var previousControllerState: PasskeyControllerState = PasskeyControllerState.Idle

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

    fun onControllerStateChanged(current: PasskeyControllerState) {
        controllerTransitionEvent(previous = previousControllerState, current = current)?.let { event ->
            when (event.level) {
                DebugLogLevel.DEBUG -> debugLogs.d(source = "controller", message = event.message)
                DebugLogLevel.INFO -> debugLogs.i(source = "controller", message = event.message)
                DebugLogLevel.WARN -> debugLogs.w(source = "controller", message = event.message)
                DebugLogLevel.ERROR -> debugLogs.e(source = "controller", message = event.message)
            }
        }

        when {
            current is PasskeyControllerState.Success && current.action == PasskeyAction.REGISTER -> {
                canRegisterStateFlow.value = false
            }

            current is PasskeyControllerState.Success && current.action == PasskeyAction.SIGN_IN -> {
                sessionStore.signIn(config.userName)
            }
        }

        previousControllerState = current
    }
}
