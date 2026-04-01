package dev.webauthn.samples.composepasskey.ui.routes

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.compose.rememberPasskeyController
import dev.webauthn.samples.composepasskey.AuthDemoCoordinator
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.DemoPasskeyServerClient
import dev.webauthn.samples.composepasskey.LocalShowDebugLogs
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import dev.webauthn.samples.composepasskey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.toDemoStatus
import dev.webauthn.samples.composepasskey.toRegistrationStartPayload
import dev.webauthn.samples.composepasskey.ui.screens.AuthScreen
import kotlinx.coroutines.launch
import org.koin.compose.koinInject

@Composable
internal fun AuthRoute() {
    val showDebugLogs = LocalShowDebugLogs.current
    val config: PasskeyDemoConfig = koinInject()
    val debugLogs: DebugLogStore = koinInject()
    val sessionStore: AppSessionStore = koinInject()
    val passkeyClient: PasskeyClient = koinInject()
    val serverClient: DemoPasskeyServerClient = koinInject()
    val scope = rememberCoroutineScope()
    val coordinator = remember(config, debugLogs, sessionStore) {
        AuthDemoCoordinator(
            config = config,
            debugLogs = debugLogs,
            sessionStore = sessionStore,
        )
    }
    val controller = rememberPasskeyController(
        serverClient = serverClient,
        passkeyClient = passkeyClient,
    )
    val controllerState by controller.uiState.collectAsState()
    val authState by coordinator.uiState.collectAsState()
    val actionsEnabled = areCeremonyActionsEnabled(controllerState)

    LaunchedEffect(controllerState) {
        coordinator.onControllerStateChanged(controllerState)
    }

    AuthScreen(
        status = controllerState.toDemoStatus(),
        actionsEnabled = actionsEnabled,
        canRegister = authState.canRegister,
        runtimeHint = authState.runtimeHint,
        onShowLogs = showDebugLogs,
        onRegister = {
            if (actionsEnabled) {
                coordinator.onRegisterClicked()
                scope.launch {
                    controller.register(config.toRegistrationStartPayload())
                }
            }
        },
        onSignIn = {
            if (actionsEnabled) {
                coordinator.onSignInClicked()
                scope.launch {
                    controller.signIn(config.toAuthenticationStartPayload())
                }
            }
        },
    )
}
