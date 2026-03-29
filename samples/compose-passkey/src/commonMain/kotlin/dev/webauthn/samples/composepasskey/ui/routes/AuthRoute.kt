package dev.webauthn.samples.composepasskey.ui.routes

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import dev.webauthn.samples.composepasskey.ui.screens.AuthScreen
import dev.webauthn.samples.composepasskey.vm.AuthViewModel
import org.koin.compose.viewmodel.koinViewModel

@Composable
internal fun AuthRoute() {
    val viewModel = koinViewModel<AuthViewModel>()
    val state by viewModel.uiState.collectAsState()

    AuthScreen(
        state = state,
        onRegister = viewModel::onRegisterClicked,
        onSignIn = viewModel::onSignInClicked,
    )
}
