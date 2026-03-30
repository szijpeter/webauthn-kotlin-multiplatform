package dev.webauthn.samples.composepasskey.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.controllerTransitionLog
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.platformRuntimeHint
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import dev.webauthn.samples.composepasskey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.toRegistrationStartPayload
import dev.webauthn.samples.composepasskey.toStatusPresentation
import dev.webauthn.samples.composepasskey.ui.state.AuthUiState
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

internal class AuthViewModel(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
) : ViewModel() {
    private val uiStateFlow: MutableStateFlow<AuthUiState> = MutableStateFlow(
        AuthUiState(runtimeHint = platformRuntimeHint()),
    )

    val uiState: StateFlow<AuthUiState> = uiStateFlow.asStateFlow()

    private var runtimeBindings: RuntimeBindings? = null
    private var controllerStateJob: Job? = null
    private var previousControllerState: PasskeyControllerState = PasskeyControllerState.Idle
    private var hasSuccessfulRegistration: Boolean = false

    init {
        debugLogs.i(source = "app", message = "First render complete")
        debugLogs.i(
            source = "app",
            message = "Config endpoint=${config.endpointBase} rpId=${config.rpId} " +
                "origin=${config.origin} user=${config.userName}",
        )
        platformRuntimeHint()?.let { hint ->
            debugLogs.w(source = "platform", message = hint)
        }
    }

    override fun onCleared() {
        controllerStateJob?.cancel()
    }

    fun bindRuntimeDependencies(
        passkeyClient: PasskeyClient,
        serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
    ) {
        val current = runtimeBindings
        if (current != null && current.passkeyClient === passkeyClient && current.serverClient === serverClient) {
            return
        }

        controllerStateJob?.cancel()

        val passkeyController = PasskeyController(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
        )
        runtimeBindings = RuntimeBindings(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
            passkeyController = passkeyController,
        )
        previousControllerState = passkeyController.uiState.value
        uiStateFlow.update {
            it.copy(
                status = passkeyController.uiState.value.toStatusPresentation(),
                actionsEnabled = areCeremonyActionsEnabled(passkeyController.uiState.value),
                canRegister = !hasSuccessfulRegistration,
            )
        }
        observeControllerState(passkeyController)
    }

    fun onRegisterClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled) return
        viewModelScope.launch {
            debugLogs.i(
                source = "action",
                message = "Register tapped endpoint=${config.endpointBase} " +
                    "rpId=${config.rpId} user=${config.userName}",
            )
            bindings.passkeyController.register(config.toRegistrationStartPayload())
        }
    }

    fun onSignInClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled) return
        viewModelScope.launch {
            debugLogs.i(
                source = "action",
                message = "Sign In tapped endpoint=${config.endpointBase} " +
                    "rpId=${config.rpId} userHandle=${config.userHandle}",
            )
            bindings.passkeyController.signIn(config.toAuthenticationStartPayload())
        }
    }

    private fun observeControllerState(
        passkeyController: PasskeyController<RegistrationStartPayload, AuthenticationStartPayload>
    ) {
        controllerStateJob = viewModelScope.launch {
            passkeyController.uiState.collect { current ->
                val transition = controllerTransitionLog(previous = previousControllerState, current = current)
                if (transition != null) {
                    when (transition.level) {
                        DebugLogLevel.DEBUG -> debugLogs.d(source = "controller", message = transition.message)
                        DebugLogLevel.INFO -> debugLogs.i(source = "controller", message = transition.message)
                        DebugLogLevel.WARN -> debugLogs.w(source = "controller", message = transition.message)
                        DebugLogLevel.ERROR -> debugLogs.e(source = "controller", message = transition.message)
                    }
                }

                uiStateFlow.update {
                    it.copy(
                        status = current.toStatusPresentation(),
                        actionsEnabled = areCeremonyActionsEnabled(current),
                        canRegister = !hasSuccessfulRegistration,
                    )
                }

                if (
                    current is PasskeyControllerState.Success &&
                    current.action == PasskeyAction.REGISTER
                ) {
                    hasSuccessfulRegistration = true
                    uiStateFlow.update { it.copy(canRegister = false) }
                }

                if (
                    current is PasskeyControllerState.Success &&
                    current.action == PasskeyAction.SIGN_IN
                ) {
                    sessionStore.signIn(config.userName)
                }

                previousControllerState = current
            }
        }
    }

    private data class RuntimeBindings(
        val passkeyClient: PasskeyClient,
        val serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
        val passkeyController: PasskeyController<RegistrationStartPayload, AuthenticationStartPayload>,
    )
}
