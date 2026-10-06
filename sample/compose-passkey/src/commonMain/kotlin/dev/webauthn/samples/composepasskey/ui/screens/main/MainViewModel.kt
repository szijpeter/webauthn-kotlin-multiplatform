package dev.webauthn.samples.composepasskey.ui.screens.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.samples.composepasskey.data.session.AppSessionState
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.domain.prf.PrfDemoResult
import dev.webauthn.samples.composepasskey.domain.prf.PrfSaltStore
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

internal class MainViewModel(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
    private val saltStore: PrfSaltStore,
    passkeyClient: PasskeyClient,
    backend: DemoPasskeyBackend,
) : ViewModel() {
    val uiState: StateFlow<MainUiState> field =
        MutableStateFlow<MainUiState>(MainUiState(userName = config.userName))

    private var foreground: Boolean = true
    private var actionJob: Job? = null
    private var actionGeneration: Long = 0

    private val prfCapability = PasskeyCapability.Extension(WebAuthnExtension.Prf)
    private val prfDemoController = PrfCryptoDemoController(
        passkeyClient = passkeyClient,
        backend = backend,
        saltStore = saltStore,
        isForeground = { foreground },
    )

    init {
        observeSession()
        uiState.update {
            it.copy(
                sessionState = PrfCryptoDemoSessionState.NoSession,
                decryptedText = null,
            )
        }
        loadCapabilities(passkeyClient)
    }

    fun onSignInWithPrfClicked() {
        runBusyAction {
            debugLogs.i(source = "prf", message = "Sign In + PRF tapped")
            prfDemoController.signInWithPrf(
                config = config,
                supportsPrf = uiState.value.supportsPrf,
            )
        }
    }

    fun onEncryptClicked() {
        runBusyAction { prfDemoController.encrypt(uiState.value.plaintext) }
    }

    fun onDecryptClicked() {
        runBusyAction { prfDemoController.decrypt() }
    }

    fun onClearSessionClicked() {
        actionGeneration += 1
        actionJob?.cancel()
        actionJob = null
        applyPrfResult(prfDemoController.clearSession())
        uiState.update { it.copy(busy = false, plaintext = "", decryptedText = null) }
    }

    fun onVisibilityChanged(isForeground: Boolean) {
        foreground = isForeground
        if (isForeground) return
        if (prfDemoController.isPlatformPromptInProgress) {
            applyPrfResult(prfDemoController.lockCurrentSession())
            uiState.update { it.copy(plaintext = "", decryptedText = null) }
        } else {
            onClearSessionClicked()
        }
    }

    override fun onCleared() {
        foreground = false
        onClearSessionClicked()
        super.onCleared()
    }

    fun onPlaintextChanged(value: String) {
        uiState.update { it.copy(plaintext = value) }
    }

    fun onLogoutClicked() {
        onClearSessionClicked()
        sessionStore.signOut()
        uiState.update {
            it.copy(
                decryptedText = null,
                sessionState = PrfCryptoDemoSessionState.NoSession,
                statusMessage = "Logged out. Sign in again to re-open PRF demo.",
            )
        }
    }

    private fun observeSession() {
        viewModelScope.launch {
            sessionStore.state.collect { state ->
                when (state) {
                    AppSessionState.SignedOut -> {
                        uiState.update { it.copy(userName = "") }
                    }

                    is AppSessionState.SignedIn -> {
                        uiState.update { it.copy(userName = state.userName) }
                    }
                }
            }
        }
    }

    private fun loadCapabilities(passkeyClient: PasskeyClient) {
        viewModelScope.launch {
            debugLogs.i(source = "capabilities", message = "Loading capability hints")
            runSuspendCatching(passkeyClient::capabilities)
                .onSuccess { loaded ->
                    uiState.update {
                        it.copy(
                            capabilities = loaded,
                            supportsPrf = loaded.supports(prfCapability),
                        )
                    }
                    debugLogs.i(
                        source = "capabilities",
                        message = "Loaded PRF=${loaded.supports(prfCapability)}",
                    )
                }
                .onFailure { _ ->
                    uiState.update {
                        it.copy(
                            capabilities = PasskeyCapabilities(),
                            supportsPrf = false,
                        )
                    }
                    debugLogs.e(
                        source = "capabilities",
                        message = "Failed to load capabilities; using defaults.",
                    )
                }
        }
    }

    private fun runBusyAction(action: suspend () -> PrfDemoResult) {
        if (uiState.value.busy) return
        val generation = ++actionGeneration
        uiState.update { it.copy(busy = true) }
        actionJob = viewModelScope.launch {
            try {
                val result = action()
                if (generation == actionGeneration) applyPrfResult(result)
            } finally {
                if (generation == actionGeneration) {
                    actionJob = null
                    uiState.update { it.copy(busy = false) }
                }
            }
        }
    }

    private fun applyPrfResult(result: PrfDemoResult) {
        uiState.update {
            it.copy(
                statusMessage = result.message,
                decryptedText = if (result is PrfDemoResult.Success) result.plaintext else it.decryptedText,
                sessionState = prfDemoController.sessionState,
            )
        }
        when (result) {
            is PrfDemoResult.Success -> debugLogs.i(source = "prf", message = result.message)
            is PrfDemoResult.Failure -> debugLogs.w(source = "prf", message = result.message)
        }
    }
}
