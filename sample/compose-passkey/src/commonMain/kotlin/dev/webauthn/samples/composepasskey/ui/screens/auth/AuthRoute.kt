package dev.webauthn.samples.composepasskey.ui.screens.auth

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import dev.webauthn.client.CeremonyFailure
import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.compose.rememberPasskeyFlow
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.samples.composepasskey.app.LocalShowDebugLogs
import dev.webauthn.samples.composepasskey.app.auth.AuthDemoCoordinator
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyError
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyState
import dev.webauthn.samples.composepasskey.domain.passkey.DemoPasskeyAction
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.toDemoStatus
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload
import kotlinx.coroutines.launch
import org.koin.compose.koinInject

@Composable
internal fun AuthRoute() {
    val showDebugLogs = LocalShowDebugLogs.current
    val config: PasskeyDemoConfig = koinInject()
    val debugLogs: DebugLogStore = koinInject()
    val sessionStore: AppSessionStore = koinInject()
    val passkeyClient: PasskeyClient = koinInject()
    val backend: DemoPasskeyBackend = koinInject()
    // docs-region compose-sample-auth-route
    val flow = rememberPasskeyFlow(passkeyClient)
    val scope = rememberCoroutineScope()
    val coordinator = remember(config, debugLogs, sessionStore) {
        AuthDemoCoordinator(config, debugLogs, sessionStore)
    }
    var state by remember { mutableStateOf<DemoCeremonyState>(DemoCeremonyState.Idle) }
    val canRegister by coordinator.canRegister.collectAsState()
    val actionsEnabled = areCeremonyActionsEnabled(state)
    // docs-endregion compose-sample-auth-route

    LaunchedEffect(state) {
        coordinator.onCeremonyStateChanged(state)
    }

    AuthScreen(
        status = state.toDemoStatus(),
        actionsEnabled = actionsEnabled,
        canRegister = canRegister,
        onShowLogs = showDebugLogs,
        onRegister = {
            if (actionsEnabled && canRegister) {
                coordinator.onRegisterClicked()
                scope.launch {
                    state = runRegistration(flow, backend, config) { state = it }
                }
            }
        },
        onSignIn = {
            if (actionsEnabled) {
                coordinator.onSignInClicked()
                scope.launch {
                    state = runAuthentication(flow, backend, config) { state = it }
                }
            }
        },
    )
}

@Suppress("TooGenericExceptionCaught")
private suspend fun runRegistration(
    flow: PasskeyFlow,
    backend: DemoPasskeyBackend,
    config: PasskeyDemoConfig,
    onPhaseChanged: (DemoCeremonyState) -> Unit,
): DemoCeremonyState {
    val action = DemoPasskeyAction.REGISTER
    return try {
        when (val result = flow.register(config.toRegistrationStartPayload(), backend.registration) {
            onPhaseChanged(DemoCeremonyState.InProgress(action, it))
        }) {
            is CeremonyResult.Success -> result.value.toState(action)
            is CeremonyResult.Failure -> result.error.toState(action)
        }
    } catch (error: Exception) {
        error.rethrowCancellation()
        DemoCeremonyState.Failure(action, DemoCeremonyError.Backend(error.message ?: "Registration failed."))
    }
}

@Suppress("TooGenericExceptionCaught")
private suspend fun runAuthentication(
    flow: PasskeyFlow,
    backend: DemoPasskeyBackend,
    config: PasskeyDemoConfig,
    onPhaseChanged: (DemoCeremonyState) -> Unit,
): DemoCeremonyState {
    val action = DemoPasskeyAction.SIGN_IN
    return try {
        when (val result = flow.signIn(config.toAuthenticationStartPayload(), backend.authentication) {
            onPhaseChanged(DemoCeremonyState.InProgress(action, it))
        }) {
            is CeremonyResult.Success -> result.value.toState(action)
            is CeremonyResult.Failure -> result.error.toState(action)
        }
    } catch (error: Exception) {
        error.rethrowCancellation()
        DemoCeremonyState.Failure(action, DemoCeremonyError.Backend(error.message ?: "Authentication failed."))
    }
}

private fun DefaultPasskeyFinishResult.toState(action: DemoPasskeyAction): DemoCeremonyState = when (this) {
    DefaultPasskeyFinishResult.Verified -> DemoCeremonyState.Success(action)
    is DefaultPasskeyFinishResult.Rejected -> DemoCeremonyState.Failure(
        action,
        DemoCeremonyError.Rejected(message ?: "The server rejected the response."),
    )
}

private fun CeremonyFailure.toState(action: DemoPasskeyAction): DemoCeremonyState = when (this) {
    CeremonyFailure.AlreadyInProgress -> DemoCeremonyState.Failure(action, DemoCeremonyError.AlreadyInProgress)
    is CeremonyFailure.Platform -> DemoCeremonyState.Failure(action, DemoCeremonyError.Platform(error))
}

private fun Exception.rethrowCancellation() {
    if (this is kotlinx.coroutines.CancellationException) throw this
}
