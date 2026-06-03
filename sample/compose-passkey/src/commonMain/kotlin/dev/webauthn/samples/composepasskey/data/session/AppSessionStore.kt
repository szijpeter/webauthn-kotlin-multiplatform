package dev.webauthn.samples.composepasskey.data.session

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

internal sealed interface AppSessionState {
    data object SignedOut : AppSessionState

    data class SignedIn(
        val userName: String,
    ) : AppSessionState
}

internal class AppSessionStore {
    val state: StateFlow<AppSessionState> field =
        MutableStateFlow<AppSessionState>(AppSessionState.SignedOut)

    fun signIn(userName: String) {
        state.value = AppSessionState.SignedIn(userName = userName)
    }

    fun signOut() {
        state.value = AppSessionState.SignedOut
    }
}
