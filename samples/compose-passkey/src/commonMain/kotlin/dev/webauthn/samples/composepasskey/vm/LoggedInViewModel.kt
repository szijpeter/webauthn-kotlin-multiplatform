package dev.webauthn.samples.composepasskey.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.DemoPasskeyServerClient
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.PrfDemoResult
import dev.webauthn.samples.composepasskey.PrfSaltStore
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
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val sessionStore: AppSessionStore,
    private val saltStore: PrfSaltStore,
    passkeyClient: PasskeyClient,
    serverClient: DemoPasskeyServerClient,
) : ViewModel() {
    private val uiStateFlow: MutableStateFlow<LoggedInUiState> =
        MutableStateFlow(LoggedInUiState(userName = config.userName))

    val uiState: StateFlow<LoggedInUiState> = uiStateFlow.asStateFlow()

    private val prfCapability = PasskeyCapability.Extension(WebAuthnExtension.Prf)
    private val prfDemoController = PrfCryptoDemoController(
        passkeyClient = passkeyClient,
        serverClient = serverClient,
        saltStore = saltStore,
    )

    init {
        observeSession()
        uiStateFlow.update {
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
                supportsPrf = uiStateFlow.value.supportsPrf,
            )
        }
    }

    fun onEncryptClicked() {
        runBusyAction { prfDemoController.encrypt(uiStateFlow.value.plaintext) }
    }

    fun onDecryptClicked() {
        runBusyAction { prfDemoController.decrypt() }
    }

    fun onClearSessionClicked() {
        applyPrfResult(prfDemoController.clearSession())
    }

    fun onPlaintextChanged(value: String) {
        uiStateFlow.update { it.copy(plaintext = value) }
    }

    fun onLogoutClicked() {
        prfDemoController.clearSession().let { clearResult ->
            if (clearResult is PrfDemoResult.Success) {
                debugLogs.i(source = "session", message = clearResult.message)
            }
        }
        sessionStore.signOut()
        uiStateFlow.update {
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
                        uiStateFlow.update { it.copy(userName = "") }
                    }

                    is AppSessionState.SignedIn -> {
                        uiStateFlow.update { it.copy(userName = state.userName) }
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

    private fun runBusyAction(action: suspend () -> PrfDemoResult) {
        if (uiStateFlow.value.busy) return
        viewModelScope.launch {
            setBusy(true)
            try {
                applyPrfResult(action())
            } finally {
                setBusy(false)
            }
        }
    }

    private fun applyPrfResult(result: PrfDemoResult) {
        when (result) {
            is PrfDemoResult.Success -> {
                updatePrfUi(
                    statusMessage = result.message,
                    decryptedText = result.plaintext,
                )
                debugLogs.i(source = "prf", message = result.message)
            }

            is PrfDemoResult.Failure -> {
                updatePrfUi(statusMessage = result.message)
                debugLogs.w(source = "prf", message = result.message)
            }
        }
    }

    private fun updatePrfUi(
        statusMessage: String,
        decryptedText: String? = uiStateFlow.value.decryptedText,
    ) {
        uiStateFlow.update {
            it.copy(
                statusMessage = statusMessage,
                decryptedText = decryptedText,
                sessionState = prfDemoController.sessionState,
            )
        }
    }

    private fun setBusy(value: Boolean) {
        uiStateFlow.update { it.copy(busy = value) }
    }
}
