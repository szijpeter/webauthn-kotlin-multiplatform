package dev.webauthn.samples.composepasskey.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.PrfDemoResult
import dev.webauthn.samples.composepasskey.session.AppSessionState
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import dev.webauthn.samples.composepasskey.ui.state.LoggedInUiState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

internal class LoggedInViewModel(
    private val passkeyClient: PasskeyClient,
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
    private val prfDemo: PrfCryptoDemoController,
) : ViewModel() {
    private val uiStateFlow: MutableStateFlow<LoggedInUiState> =
        MutableStateFlow(LoggedInUiState(userName = config.userName))

    val uiState: StateFlow<LoggedInUiState> = uiStateFlow.asStateFlow()

    val debugEntries
        get() = debugLogs.entries

    private val prfCapability = PasskeyCapability.Extension(WebAuthnExtension.Prf)

    init {
        observeSession()
        loadCapabilities()
    }

    fun onSignInWithPrfClicked() {
        if (uiStateFlow.value.busy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                debugLogs.i(source = "prf", message = "Sign In + PRF tapped for ${config.userName}")
                val result = prfDemo.signInWithPrf(
                    config = config,
                    supportsPrf = uiStateFlow.value.supportsPrf,
                )
                applyPrfResult(result)
            } finally {
                setBusy(false)
            }
        }
    }

    fun onEncryptClicked() {
        if (uiStateFlow.value.busy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                applyPrfResult(prfDemo.encrypt(uiStateFlow.value.plaintext))
            } finally {
                setBusy(false)
            }
        }
    }

    fun onDecryptClicked() {
        if (uiStateFlow.value.busy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                applyPrfResult(prfDemo.decrypt())
            } finally {
                setBusy(false)
            }
        }
    }

    fun onClearSessionClicked() {
        applyPrfResult(prfDemo.clearSession())
    }

    fun onPlaintextChanged(value: String) {
        uiStateFlow.update { it.copy(plaintext = value) }
    }

    fun onLogoutClicked() {
        val clearResult = prfDemo.clearSession()
        if (clearResult is PrfDemoResult.Success) {
            debugLogs.i(source = "session", message = clearResult.message)
        }
        sessionStore.signOut()
        uiStateFlow.update {
            it.copy(
                decryptedText = null,
                statusMessage = "Logged out. Sign in again to re-open PRF demo.",
            )
        }
    }

    private fun observeSession() {
        viewModelScope.launch {
            sessionStore.state.collect { state ->
                when (state) {
                    AppSessionState.SignedOut -> {
                        uiStateFlow.update { it.copy(userName = "") }
                    }

                    is AppSessionState.SignedIn -> {
                        uiStateFlow.update { it.copy(userName = state.userName) }
                    }
                }
            }
        }
    }

    private fun loadCapabilities() {
        viewModelScope.launch {
            debugLogs.i(source = "capabilities", message = "Loading capability hints")
            runSuspendCatching(passkeyClient::capabilities)
                .onSuccess { loaded ->
                    uiStateFlow.update {
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
                .onFailure { throwable ->
                    uiStateFlow.update {
                        it.copy(
                            capabilities = PasskeyCapabilities(),
                            supportsPrf = false,
                        )
                    }
                    debugLogs.e(
                        source = "capabilities",
                        message = "Failed to load capabilities: ${throwable.message ?: "using defaults"}",
                        throwable = throwable,
                    )
                }
        }
    }

    private fun applyPrfResult(result: PrfDemoResult) {
        when (result) {
            is PrfDemoResult.Success -> {
                uiStateFlow.update {
                    it.copy(
                        statusMessage = result.message,
                        decryptedText = result.plaintext,
                        sessionState = prfDemo.sessionState,
                    )
                }
                debugLogs.i(source = "prf", message = result.message)
            }

            is PrfDemoResult.Failure -> {
                uiStateFlow.update {
                    it.copy(
                        statusMessage = result.message,
                        sessionState = prfDemo.sessionState,
                    )
                }
                debugLogs.w(source = "prf", message = result.message)
            }
        }
    }

    private fun setBusy(value: Boolean) {
        uiStateFlow.update { it.copy(busy = value) }
    }
}
