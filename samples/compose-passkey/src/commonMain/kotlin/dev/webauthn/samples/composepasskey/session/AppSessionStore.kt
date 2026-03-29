package dev.webauthn.samples.composepasskey.session

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

internal sealed interface AppSessionState {
    data object SignedOut : AppSessionState

    data class SignedIn(
        val userName: String,
    ) : AppSessionState
}

internal class AppSessionStore {
    private val stateFlow: MutableStateFlow<AppSessionState> = MutableStateFlow(AppSessionState.SignedOut)

    val state: StateFlow<AppSessionState> = stateFlow.asStateFlow()

    fun signIn(userName: String) {
        stateFlow.value = AppSessionState.SignedIn(userName = userName)
    }

    fun signOut() {
        stateFlow.value = AppSessionState.SignedOut
    }
}
