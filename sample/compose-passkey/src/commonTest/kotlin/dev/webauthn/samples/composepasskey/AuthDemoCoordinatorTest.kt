package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.samples.composepasskey.app.auth.AuthDemoCoordinator
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionState
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.signals.CredentialSignalDemoClient
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuthDemoCoordinatorTest {
    @Test
    fun register_success_disables_register_after_logging_action_and_transition() = runTest {
        val debugLogs = DebugLogStore()
        val sessionStore = AppSessionStore()
        val coordinator = AuthDemoCoordinator(
            config = testDemoConfig(),
            debugLogs = debugLogs,
            sessionStore = sessionStore,
            credentialSignalClient = FakeCredentialSignalDemoClient(),
        )

        coordinator.onRegisterClicked()
        coordinator.onControllerStateChanged(
            PasskeyControllerState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.STARTING,
            ),
        )
        coordinator.onControllerStateChanged(PasskeyControllerState.Success(PasskeyAction.REGISTER))

        assertFalse(coordinator.canRegister.value)
        assertTrue(debugLogs.entries.any { it.source == "action" && it.message.contains("Register tapped") })
        assertTrue(debugLogs.entries.any { it.source == "controller" && it.message.contains("Register success") })
    }

    @Test
    fun sign_in_success_opens_local_session_and_logs_transition() = runTest {
        val debugLogs = DebugLogStore()
        val sessionStore = AppSessionStore()
        val credentialSignalClient = FakeCredentialSignalDemoClient()
        val coordinator = AuthDemoCoordinator(
            config = testDemoConfig(),
            debugLogs = debugLogs,
            sessionStore = sessionStore,
            credentialSignalClient = credentialSignalClient,
        )

        coordinator.onSignInClicked()
        coordinator.onControllerStateChanged(PasskeyControllerState.Success(PasskeyAction.SIGN_IN))

        assertEquals(
            AppSessionState.SignedIn(userName = "demo@local"),
            sessionStore.state.value,
        )
        assertTrue(debugLogs.entries.any { it.source == "action" && it.message.contains("Sign In tapped") })
        assertTrue(debugLogs.entries.any { it.source == "controller" && it.message.contains("Sign In success") })
        assertEquals(1, credentialSignalClient.currentUserDetailsCalls)
        assertEquals("example.test", credentialSignalClient.lastRpId?.value)
        assertEquals("ZGVtby11c2VyLTE", credentialSignalClient.lastUserId?.value?.encoded())
        assertTrue(debugLogs.entries.any { it.source == "signals" && it.message.contains("accepted") })
    }
}

private class FakeCredentialSignalDemoClient : CredentialSignalDemoClient {
    var currentUserDetailsCalls: Int = 0
    var lastRpId: RpId? = null
    var lastUserId: UserHandle? = null

    override val isAvailable: Boolean = true

    override suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
    ): PasskeyResult<Unit> {
        currentUserDetailsCalls += 1
        lastRpId = rpId
        lastUserId = userId
        return PasskeyResult.Success(Unit)
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
