package dev.webauthn.samples.composepasskey.app.auth

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.controllerTransitionEvent
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload
import dev.webauthn.samples.composepasskey.domain.signals.CredentialSignalDemoClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

internal class AuthDemoCoordinator(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
    private val credentialSignalClient: CredentialSignalDemoClient,
) {
    val canRegister: StateFlow<Boolean> field = MutableStateFlow<Boolean>(true)

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

    suspend fun onControllerStateChanged(current: PasskeyControllerState) {
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
                canRegister.value = false
            }

            current is PasskeyControllerState.Success && current.action == PasskeyAction.SIGN_IN -> {
                sessionStore.signIn(config.userName)
                signalCurrentUserDetails()
            }
        }

        previousControllerState = current
    }

    private suspend fun signalCurrentUserDetails() {
        if (!credentialSignalClient.isAvailable) return
        val rpId = when (val result = RpId.parse(config.rpId)) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> {
                debugLogs.w(source = "signals", message = "Skipped current user details signal: invalid RP ID")
                return
            }
        }
        val userHandle = when (val result = UserHandle.parse(config.toRegistrationStartPayload().userHandle)) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> {
                debugLogs.w(source = "signals", message = "Skipped current user details signal: invalid user handle")
                return
            }
        }
        when (
            val result = credentialSignalClient.signalCurrentUserDetails(
                rpId = rpId,
                userId = userHandle,
                name = config.userName,
                displayName = config.userName,
            )
        ) {
            is PasskeyResult.Success -> {
                debugLogs.i(source = "signals", message = "Current user details signal accepted")
            }

            is PasskeyResult.Failure -> {
                debugLogs.w(source = "signals", message = result.error.message)
            }
        }
    }
}
