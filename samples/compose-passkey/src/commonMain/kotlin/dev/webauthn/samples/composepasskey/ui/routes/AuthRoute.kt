package dev.webauthn.samples.composepasskey.ui.routes

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import dev.webauthn.samples.composepasskey.LocalAuthRuntimeDependencies
import dev.webauthn.samples.composepasskey.ui.screens.AuthScreen
import dev.webauthn.samples.composepasskey.vm.AuthViewModel
import org.koin.compose.viewmodel.koinViewModel

@Composable
internal fun AuthRoute() {
    val runtimeDependencies = LocalAuthRuntimeDependencies.current
    val viewModelStoreOwner = rememberRouteViewModelStoreOwner()
    val viewModel = koinViewModel<AuthViewModel>(viewModelStoreOwner = viewModelStoreOwner)
    LaunchedEffect(runtimeDependencies.passkeyClient, runtimeDependencies.serverClient) {
        viewModel.bindRuntimeDependencies(
            passkeyClient = runtimeDependencies.passkeyClient,
            serverClient = runtimeDependencies.serverClient,
        )
    }
    val state by viewModel.uiState.collectAsState()

    AuthScreen(
        state = state,
        debugEntries = viewModel.debugEntries,
        onRegister = viewModel::onRegisterClicked,
        onSignIn = viewModel::onSignInClicked,
        onSignInWithPrf = viewModel::onSignInWithPrfClicked,
        onEncrypt = viewModel::onEncryptClicked,
        onDecrypt = viewModel::onDecryptClicked,
        onClearPrfSession = viewModel::onClearSessionClicked,
        onPlaintextChange = viewModel::onPlaintextChanged,
    )
}

@Composable
private fun rememberRouteViewModelStoreOwner(): ViewModelStoreOwner {
    val owner = remember { RouteViewModelStoreOwner() }
    DisposableEffect(owner) {
        onDispose {
            owner.viewModelStore.clear()
        }
    }
    return owner
}

private class RouteViewModelStoreOwner : ViewModelStoreOwner {
    override val viewModelStore: ViewModelStore = ViewModelStore()
}
