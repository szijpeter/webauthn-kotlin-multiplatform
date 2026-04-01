package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.samples.composepasskey.session.AppSessionState
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuthDemoCoordinatorTest {
    @Test
    fun register_success_disables_register_after_logging_action_and_transition() {
        val debugLogs = DebugLogStore()
        val sessionStore = AppSessionStore()
        val coordinator = AuthDemoCoordinator(
            config = testDemoConfig(),
            debugLogs = debugLogs,
            sessionStore = sessionStore,
            runtimeHint = "Provider hint",
        )

        coordinator.onRegisterClicked()
        coordinator.onControllerStateChanged(
            PasskeyControllerState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.STARTING,
            ),
        )
        coordinator.onControllerStateChanged(PasskeyControllerState.Success(PasskeyAction.REGISTER))

        assertFalse(coordinator.uiState.value.canRegister)
        assertEquals("Provider hint", coordinator.uiState.value.runtimeHint)
        assertTrue(debugLogs.entries.any { it.source == "action" && it.message.contains("Register tapped") })
        assertTrue(debugLogs.entries.any { it.source == "controller" && it.message.contains("Register success") })
    }

    @Test
    fun sign_in_success_opens_local_session_and_logs_transition() {
        val debugLogs = DebugLogStore()
        val sessionStore = AppSessionStore()
        val coordinator = AuthDemoCoordinator(
            config = testDemoConfig(),
            debugLogs = debugLogs,
            sessionStore = sessionStore,
        )

        coordinator.onSignInClicked()
        coordinator.onControllerStateChanged(PasskeyControllerState.Success(PasskeyAction.SIGN_IN))

        assertEquals(
            AppSessionState.SignedIn(userName = "demo@local"),
            sessionStore.state.value,
        )
        assertTrue(debugLogs.entries.any { it.source == "action" && it.message.contains("Sign In tapped") })
        assertTrue(debugLogs.entries.any { it.source == "controller" && it.message.contains("Sign In success") })
    }
}

private fun testDemoConfig(): PasskeyDemoConfig {
    return PasskeyDemoConfig(
        endpointBase = "https://example.test",
        rpId = "example.test",
        origin = "https://example.test",
        userHandle = "demo-user-1",
        userName = "demo@local",
    )
}
