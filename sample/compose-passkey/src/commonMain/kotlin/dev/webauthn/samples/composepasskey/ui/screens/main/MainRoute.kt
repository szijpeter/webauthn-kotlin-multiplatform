package dev.webauthn.samples.composepasskey.ui.screens.main

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import dev.webauthn.samples.composepasskey.app.LocalShowDebugLogs
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import org.koin.compose.koinInject
import org.koin.compose.viewmodel.koinViewModel

@Composable
internal fun MainRoute() {
    val showDebugLogs = LocalShowDebugLogs.current
    val viewModel = koinViewModel<MainViewModel>()
    val state by viewModel.uiState.collectAsState()

    MainScreen(
        config = koinInject<PasskeyDemoConfig>(),
        state = state,
        onShowLogs = showDebugLogs,
        onSignInWithPrf = viewModel::onSignInWithPrfClicked,
        onEncrypt = viewModel::onEncryptClicked,
        onDecrypt = viewModel::onDecryptClicked,
        onClearPrfSession = viewModel::onClearSessionClicked,
        onPlaintextChange = viewModel::onPlaintextChanged,
        onLogout = viewModel::onLogoutClicked,
    )
}
