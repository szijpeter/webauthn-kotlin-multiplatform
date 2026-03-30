package dev.webauthn.samples.composepasskey.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.PrfDemoResult
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.PrfSaltStore
import dev.webauthn.samples.composepasskey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.controllerTransitionLog
import dev.webauthn.samples.composepasskey.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.platformRuntimeHint
import dev.webauthn.samples.composepasskey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.toRegistrationStartPayload
import dev.webauthn.samples.composepasskey.toStatusPresentation
import dev.webauthn.samples.composepasskey.ui.state.AuthUiState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

internal class AuthViewModel(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val saltStore: PrfSaltStore,
) : ViewModel() {
    private val uiStateFlow: MutableStateFlow<AuthUiState> = MutableStateFlow(
        AuthUiState(runtimeHint = platformRuntimeHint()),
    )

    val uiState: StateFlow<AuthUiState> = uiStateFlow.asStateFlow()

    val debugEntries: List<DebugLogEntry>
        get() = debugLogs.entries

    private var runtimeBindings: RuntimeBindings? = null
    private var controllerStateJob: Job? = null

    private val prfCapability = PasskeyCapability.Extension(WebAuthnExtension.Prf)
    private var previousControllerState: PasskeyControllerState = PasskeyControllerState.Idle

    init {
        debugLogs.i(source = "app", message = "First render complete")
        debugLogs.i(
            source = "app",
            message = "Config endpoint=${config.endpointBase} rpId=${config.rpId} origin=${config.origin} user=${config.userName}",
        )
        platformRuntimeHint()?.let { hint ->
            debugLogs.w(source = "platform", message = hint)
        }
    }

    override fun onCleared() {
        controllerStateJob?.cancel()
        runtimeBindings?.prfDemo?.clearSession()
    }

    fun bindRuntimeDependencies(
        passkeyClient: PasskeyClient,
        serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
    ) {
        val current = runtimeBindings
        if (current != null && current.passkeyClient === passkeyClient && current.serverClient === serverClient) {
            return
        }

        current?.prfDemo?.clearSession()
        controllerStateJob?.cancel()

        val controller = PasskeyController(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
        )
        val prfDemo = PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
            saltStore = saltStore,
        )
        runtimeBindings = RuntimeBindings(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
            passkeyController = controller,
            prfDemo = prfDemo,
        )
        previousControllerState = controller.uiState.value
        uiStateFlow.update {
            it.copy(
                status = controller.uiState.value.toStatusPresentation(),
                actionsEnabled = areCeremonyActionsEnabled(controller.uiState.value),
                prfSessionState = prfDemo.sessionState,
            )
        }
        observeControllerState(controller)
        loadCapabilities(passkeyClient)
    }

    fun onRegisterClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            debugLogs.i(
                source = "action",
                message = "Register tapped endpoint=${config.endpointBase} rpId=${config.rpId} user=${config.userName}",
            )
            bindings.passkeyController.register(config.toRegistrationStartPayload())
        }
    }

    fun onSignInClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            debugLogs.i(
                source = "action",
                message = "Sign In tapped endpoint=${config.endpointBase} rpId=${config.rpId} userHandle=${config.userHandle}",
            )
            bindings.passkeyController.signIn(config.toAuthenticationStartPayload())
        }
    }

    fun onSignInWithPrfClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                debugLogs.i(source = "prf", message = "Sign In + PRF tapped for ${config.userName}")
                val supportsPrf = uiStateFlow.value.capabilities.supports(prfCapability)
                when (val result = bindings.prfDemo.signInWithPrf(config = config, supportsPrf = supportsPrf)) {
                    is PrfDemoResult.Success -> {
                        debugLogs.i(source = "prf", message = result.message)
                        updatePrfStatus(
                            statusMessage = result.message,
                            decryptedText = null,
                        )
                    }

                    is PrfDemoResult.Failure -> {
                        debugLogs.w(source = "prf", message = result.message)
                        updatePrfStatus(
                            statusMessage = result.message,
                            decryptedText = null,
                        )
                    }
                }
                syncPrfSessionState(bindings.prfDemo)
            } finally {
                setBusy(false)
            }
        }
    }

    fun onEncryptClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                when (val result = bindings.prfDemo.encrypt(uiStateFlow.value.prfPlaintext)) {
                    is PrfDemoResult.Success -> {
                        debugLogs.i(source = "prf", message = result.message)
                        updatePrfStatus(
                            statusMessage = result.message,
                            decryptedText = null,
                        )
                    }

                    is PrfDemoResult.Failure -> {
                        debugLogs.w(source = "prf", message = result.message)
                        updatePrfStatus(
                            statusMessage = result.message,
                            decryptedText = null,
                        )
                    }
                }
                syncPrfSessionState(bindings.prfDemo)
            } finally {
                setBusy(false)
            }
        }
    }

    fun onDecryptClicked() {
        val bindings = runtimeBindings ?: return
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                when (val result = bindings.prfDemo.decrypt()) {
                    is PrfDemoResult.Success -> {
                        debugLogs.i(source = "prf", message = result.message)
                        updatePrfStatus(
                            statusMessage = result.message,
                            decryptedText = result.plaintext,
                        )
                    }

                    is PrfDemoResult.Failure -> {
                        debugLogs.w(source = "prf", message = result.message)
                        updatePrfStatus(
                            statusMessage = result.message,
                            decryptedText = null,
                        )
                    }
                }
                syncPrfSessionState(bindings.prfDemo)
            } finally {
                setBusy(false)
            }
        }
    }

    fun onClearSessionClicked() {
        val bindings = runtimeBindings ?: return
        when (val result = bindings.prfDemo.clearSession()) {
            is PrfDemoResult.Success -> {
                debugLogs.i(source = "prf", message = result.message)
                updatePrfStatus(
                    statusMessage = result.message,
                    decryptedText = null,
                )
            }

            is PrfDemoResult.Failure -> {
                debugLogs.w(source = "prf", message = result.message)
                updatePrfStatus(
                    statusMessage = result.message,
                    decryptedText = null,
                )
            }
        }
        syncPrfSessionState(bindings.prfDemo)
    }

    fun onPlaintextChanged(value: String) {
        uiStateFlow.update { it.copy(prfPlaintext = value) }
    }

    private fun observeControllerState(passkeyController: PasskeyController<RegistrationStartPayload, AuthenticationStartPayload>) {
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
                    )
                }
                previousControllerState = current
            }
        }
    }

    private fun loadCapabilities(passkeyClient: PasskeyClient) {
        viewModelScope.launch {
            debugLogs.i(source = "capabilities", message = "Loading capability hints")
            runSuspendCatching(passkeyClient::capabilities)
                .onSuccess { loaded ->
                    uiStateFlow.update { it.copy(capabilities = loaded) }
                    debugLogs.i(
                        source = "capabilities",
                        message = "Loaded PRF=${loaded.supports(prfCapability)}",
                    )
                }
                .onFailure { throwable ->
                    uiStateFlow.update { it.copy(capabilities = PasskeyCapabilities()) }
                    debugLogs.e(
                        source = "capabilities",
                        message = "Failed to load capabilities: ${throwable.message ?: "using defaults"}",
                        throwable = throwable,
                    )
                }
        }
    }

    private fun setBusy(value: Boolean) {
        uiStateFlow.update { it.copy(prfBusy = value) }
    }

    private fun updatePrfStatus(statusMessage: String, decryptedText: String?) {
        uiStateFlow.update {
            it.copy(
                prfStatusMessage = statusMessage,
                prfDecryptedText = decryptedText,
            )
        }
    }

    private fun syncPrfSessionState(prfDemo: PrfCryptoDemoController?) {
        uiStateFlow.update {
            it.copy(prfSessionState = prfDemo?.sessionState ?: PrfCryptoDemoSessionState.NoSession)
        }
    }

    private data class RuntimeBindings(
        val passkeyClient: PasskeyClient,
        val serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
        val passkeyController: PasskeyController<RegistrationStartPayload, AuthenticationStartPayload>,
        val prfDemo: PrfCryptoDemoController,
    )
}
