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
import kotlinx.coroutines.launch

internal class AuthViewModel(
    passkeyClient: PasskeyClient,
    serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    saltStore: PrfSaltStore,
) : ViewModel() {
    private val uiStateFlow: MutableStateFlow<AuthUiState> = MutableStateFlow(
        AuthUiState(runtimeHint = platformRuntimeHint()),
    )

    val uiState: StateFlow<AuthUiState> = uiStateFlow.asStateFlow()

    val debugEntries: List<DebugLogEntry>
        get() = debugLogs.entries

    private val passkeyController = PasskeyController(passkeyClient = passkeyClient, serverClient = serverClient)
    private val prfDemo = PrfCryptoDemoController(
        passkeyClient = passkeyClient,
        serverClient = serverClient,
        saltStore = saltStore,
    )

    private val prfCapability = PasskeyCapability.Extension(WebAuthnExtension.Prf)
    private var previousControllerState: PasskeyControllerState = passkeyController.uiState.value

    init {
        debugLogs.i(source = "app", message = "First render complete")
        debugLogs.i(
            source = "app",
            message = "Config endpoint=${config.endpointBase} rpId=${config.rpId} origin=${config.origin} user=${config.userName}",
        )
        platformRuntimeHint()?.let { hint ->
            debugLogs.w(source = "platform", message = hint)
        }

        observeControllerState()
        loadCapabilities(passkeyClient)
    }

    override fun onCleared() {
        prfDemo.clearSession()
    }

    fun onRegisterClicked() {
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            debugLogs.i(
                source = "action",
                message = "Register tapped endpoint=${config.endpointBase} rpId=${config.rpId} user=${config.userName}",
            )
            passkeyController.register(config.toRegistrationStartPayload())
        }
    }

    fun onSignInClicked() {
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            debugLogs.i(
                source = "action",
                message = "Sign In tapped endpoint=${config.endpointBase} rpId=${config.rpId} userHandle=${config.userHandle}",
            )
            passkeyController.signIn(config.toAuthenticationStartPayload())
        }
    }

    fun onSignInWithPrfClicked() {
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                debugLogs.i(source = "prf", message = "Sign In + PRF tapped for ${config.userName}")
                val supportsPrf = uiStateFlow.value.capabilities.supports(prfCapability)
                when (val result = prfDemo.signInWithPrf(config = config, supportsPrf = supportsPrf)) {
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
                syncPrfSessionState()
            } finally {
                setBusy(false)
            }
        }
    }

    fun onEncryptClicked() {
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                when (val result = prfDemo.encrypt(uiStateFlow.value.prfPlaintext)) {
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
                syncPrfSessionState()
            } finally {
                setBusy(false)
            }
        }
    }

    fun onDecryptClicked() {
        if (!uiStateFlow.value.actionsEnabled || uiStateFlow.value.prfBusy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                when (val result = prfDemo.decrypt()) {
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
                syncPrfSessionState()
            } finally {
                setBusy(false)
            }
        }
    }

    fun onClearSessionClicked() {
        when (val result = prfDemo.clearSession()) {
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
        syncPrfSessionState()
    }

    fun onPlaintextChanged(value: String) {
        uiStateFlow.update { it.copy(prfPlaintext = value) }
    }

    private fun observeControllerState() {
        viewModelScope.launch {
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

    private fun syncPrfSessionState() {
        uiStateFlow.update {
            it.copy(prfSessionState = prfDemo.sessionState)
        }
    }
}
