package dev.webauthn.samples.composepasskey.ui.screens.main

import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.restore.RestoreCredentialDemoController
import dev.webauthn.samples.composepasskey.domain.restore.RestoreCredentialDemoResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

internal class RestoreCredentialUiActions(
    private val config: PasskeyDemoConfig,
    private val debugLogs: DebugLogStore,
    private val controller: RestoreCredentialDemoController,
    private val uiState: MutableStateFlow<MainUiState>,
    private val scope: CoroutineScope,
    private val setBusy: (Boolean) -> Unit,
) {
    val isAvailable: Boolean
        get() = controller.isAvailable

    fun createRestoreCredential() {
        runAction(
            logMessage = "Create restore key tapped",
            action = { controller.createRestoreCredential(config) },
        )
    }

    fun getRestoreCredential() {
        runAction(
            logMessage = "Restore sign-in tapped",
            action = { controller.getRestoreCredential(config) },
        )
    }

    fun clearRestoreCredential() {
        runAction(
            logMessage = "Clear restore key tapped",
            action = { controller.clearRestoreCredential() },
        )
    }

    suspend fun clearForLogout() {
        if (controller.isAvailable) {
            applyResult(controller.clearRestoreCredential())
        }
    }

    fun initialStatus(): String {
        return if (controller.isAvailable) {
            "Restore credential lifecycle is ready."
        } else {
            "Restore Credentials are Android-only in this sample."
        }
    }

    private fun runAction(
        logMessage: String,
        action: suspend () -> RestoreCredentialDemoResult,
    ) {
        if (uiState.value.busy) return
        setBusy(true)
        scope.launch {
            try {
                debugLogs.i(source = "restore", message = logMessage)
                applyResult(action())
            } finally {
                setBusy(false)
            }
        }
    }

    private fun applyResult(result: RestoreCredentialDemoResult) {
        when (result) {
            is RestoreCredentialDemoResult.Success -> {
                updateUi(result.message)
                debugLogs.i(source = "restore", message = result.message)
            }

            is RestoreCredentialDemoResult.Failure -> {
                updateUi(result.message)
                debugLogs.w(source = "restore", message = result.message)
            }
        }
    }

    private fun updateUi(statusMessage: String) {
        uiState.update { it.copy(restoreStatusMessage = statusMessage) }
    }
}
