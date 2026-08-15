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
import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.compose.rememberPasskeyFlow
import dev.webauthn.samples.composepasskey.app.LocalShowDebugLogs
import dev.webauthn.samples.composepasskey.app.auth.AuthDemoCoordinator
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
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
    val scope = rememberCoroutineScope()
    val coordinator = remember(config, debugLogs, sessionStore) {
        AuthDemoCoordinator(
            config = config,
            debugLogs = debugLogs,
            sessionStore = sessionStore,
        )
    }
    // docs-region compose-sample-auth-route
    val flow = rememberPasskeyFlow(passkeyClient)
    var controllerState by remember { mutableStateOf<PasskeyControllerState>(PasskeyControllerState.Idle) }
    val canRegister by coordinator.canRegister.collectAsState()
    val actionsEnabled = areCeremonyActionsEnabled(controllerState)
    // docs-endregion compose-sample-auth-route

    LaunchedEffect(controllerState) {
        coordinator.onControllerStateChanged(controllerState)
    }

    AuthScreen(
        status = controllerState.toDemoStatus(),
        actionsEnabled = actionsEnabled,
        canRegister = canRegister,
        onShowLogs = showDebugLogs,
        onRegister = {
            if (actionsEnabled && canRegister) {
                coordinator.onRegisterClicked()
                scope.launch {
                    controllerState = flow.register(
                        input = config.toRegistrationStartPayload(),
                        backend = backend.registrationBackend(),
                        onPhaseChanged = { phase ->
                            controllerState = PasskeyControllerState.InProgress(PasskeyAction.REGISTER, phase)
                        },
                    ).toDemoControllerState(PasskeyAction.REGISTER)
                }
            }
        },
        onSignIn = {
            if (actionsEnabled) {
                coordinator.onSignInClicked()
                scope.launch {
                    controllerState = flow.signIn(
                        input = config.toAuthenticationStartPayload(),
                        backend = backend.authenticationBackend(),
                        onPhaseChanged = { phase ->
                            controllerState = PasskeyControllerState.InProgress(PasskeyAction.SIGN_IN, phase)
                        },
                    ).toDemoControllerState(PasskeyAction.SIGN_IN)
                }
            }
        },
    )
}

internal fun CeremonyResult<PasskeyFinishResult>.toDemoControllerState(
    action: PasskeyAction,
): PasskeyControllerState = when (this) {
    is CeremonyResult.Success -> when (val result = value) {
        PasskeyFinishResult.Verified -> PasskeyControllerState.Success(action)
        is PasskeyFinishResult.Rejected -> PasskeyControllerState.Failure(
            action = action,
            error = PasskeyClientError.Transport(result.message ?: "The server rejected the passkey response."),
        )
    }

    is CeremonyResult.Failure -> PasskeyControllerState.Failure(
        action = action,
        error = when (val failure = error) {
            CeremonyFailure.AlreadyInProgress ->
                PasskeyClientError.Transport("A passkey ceremony is already in progress.")
            is CeremonyFailure.Backend -> PasskeyClientError.Transport(failure.message)
            is CeremonyFailure.Platform -> failure.error
        },
    )
}
