package dev.webauthn.samples.composepasskey.ui.auth

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.compose.rememberPasskeyController
import dev.webauthn.samples.composepasskey.app.LocalShowDebugLogs
import dev.webauthn.samples.composepasskey.app.auth.AuthDemoCoordinator
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyServerClient
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
    val canRegister by coordinator.canRegister.collectAsState()
    val actionsEnabled = areCeremonyActionsEnabled(controllerState)

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
