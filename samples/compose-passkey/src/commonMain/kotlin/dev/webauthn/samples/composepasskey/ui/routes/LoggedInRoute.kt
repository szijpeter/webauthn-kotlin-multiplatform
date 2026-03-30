package dev.webauthn.samples.composepasskey.ui.routes

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import dev.webauthn.samples.composepasskey.LocalRevealDebugLogs
import dev.webauthn.samples.composepasskey.ui.screens.LoggedInScreen
import dev.webauthn.samples.composepasskey.vm.LoggedInViewModel
import org.koin.compose.viewmodel.koinViewModel

@Composable
internal fun LoggedInRoute() {
    val revealDebugLogs = LocalRevealDebugLogs.current
    val viewModel = koinViewModel<LoggedInViewModel>()
    val state by viewModel.uiState.collectAsState()

    LoggedInScreen(
        state = state,
        onHeaderSecretTap = revealDebugLogs,
        onSignInWithPrf = viewModel::onSignInWithPrfClicked,
        onEncrypt = viewModel::onEncryptClicked,
        onDecrypt = viewModel::onDecryptClicked,
        onClearPrfSession = viewModel::onClearSessionClicked,
        onPlaintextChange = viewModel::onPlaintextChanged,
        onLogout = viewModel::onLogoutClicked,
    )
}
