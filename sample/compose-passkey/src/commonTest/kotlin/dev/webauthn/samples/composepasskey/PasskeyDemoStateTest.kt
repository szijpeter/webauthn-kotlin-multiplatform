package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.client.PlatformCapability
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.samples.composepasskey.app.auth.AuthDemoCoordinator
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionState
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.model.StatusTone
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyError
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyState
import dev.webauthn.samples.composepasskey.domain.passkey.DemoPasskeyAction
import dev.webauthn.samples.composepasskey.domain.passkey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.domain.passkey.demoTransitionEvent
import dev.webauthn.samples.composepasskey.domain.passkey.toDemoStatus
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.ui.screens.auth.canStartConditionalRegistration
import dev.webauthn.samples.composepasskey.ui.screens.auth.canStartExplicitRegistration
import dev.webauthn.samples.composepasskey.ui.screens.auth.supportsConditionalCreate
import dev.webauthn.samples.composepasskey.domain.signals.CredentialSignalDemoClient
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasskeyDemoStateTest {
    @Test
    fun explicit_registration_does_not_require_conditional_create_support() {
        assertTrue(canStartExplicitRegistration(actionsEnabled = true, canRegister = true))
        assertFalse(canStartExplicitRegistration(actionsEnabled = false, canRegister = true))
        assertFalse(canStartExplicitRegistration(actionsEnabled = true, canRegister = false))

        assertTrue(
            canStartConditionalRegistration(
                actionsEnabled = true,
                canRegister = true,
                conditionalCreateAvailable = true,
            ),
        )
        assertFalse(
            canStartConditionalRegistration(
                actionsEnabled = true,
                canRegister = true,
                conditionalCreateAvailable = false,
            ),
        )
    }

    @Test
    fun conditional_create_action_requires_a_supported_platform_capability() {
        val capability = PasskeyCapability.Platform(PlatformCapability.ConditionalCreate)

        assertTrue(
            PasskeyCapabilities(mapOf(capability to CapabilitySupport.SUPPORTED))
                .supportsConditionalCreate(),
        )
        assertFalse(
            PasskeyCapabilities(mapOf(capability to CapabilitySupport.UNSUPPORTED))
                .supportsConditionalCreate(),
        )
        assertFalse(PasskeyCapabilities().supportsConditionalCreate())
    }

    @Test
    fun actions_are_disabled_only_while_a_ceremony_is_in_progress() {
        assertTrue(areCeremonyActionsEnabled(DemoCeremonyState.Idle))
        assertFalse(
            areCeremonyActionsEnabled(
                DemoCeremonyState.InProgress(DemoPasskeyAction.REGISTER, PasskeyPhase.STARTING),
            ),
        )
        assertTrue(areCeremonyActionsEnabled(DemoCeremonyState.Success(DemoPasskeyAction.SIGN_IN)))
    }

    @Test
    fun transitions_log_start_success_and_cancel_as_warning() {
        val started = demoTransitionEvent(
            DemoCeremonyState.Idle,
            DemoCeremonyState.InProgress(DemoPasskeyAction.REGISTER, PasskeyPhase.STARTING),
        )
        val completed = demoTransitionEvent(
            DemoCeremonyState.InProgress(DemoPasskeyAction.REGISTER, PasskeyPhase.FINISHING),
            DemoCeremonyState.Success(DemoPasskeyAction.REGISTER),
        )
        val cancelled = demoTransitionEvent(
            DemoCeremonyState.InProgress(DemoPasskeyAction.SIGN_IN, PasskeyPhase.PLATFORM_PROMPT),
            DemoCeremonyState.Failure(
                DemoPasskeyAction.SIGN_IN,
                DemoCeremonyError.Platform(PasskeyClientError.UserCancelled("cancelled")),
            ),
        )

        assertEquals(DebugLogLevel.INFO, started?.level)
        assertTrue(started?.message.orEmpty().contains("starting"))
        assertEquals(DebugLogLevel.INFO, completed?.level)
        assertEquals(DebugLogLevel.WARN, cancelled?.level)
    }

    @Test
    fun status_preserves_failure_category_and_cancel_warning() {
        val cancelled = DemoCeremonyState.Failure(
            DemoPasskeyAction.SIGN_IN,
            DemoCeremonyError.Platform(PasskeyClientError.UserCancelled("cancelled")),
        ).toDemoStatus()
        val rejected = DemoCeremonyState.Failure(
            DemoPasskeyAction.REGISTER,
            DemoCeremonyError.Rejected("invalid response"),
        ).toDemoStatus()

        assertEquals(StatusTone.WARNING, cancelled.tone)
        assertEquals(StatusTone.ERROR, rejected.tone)
        assertTrue(rejected.detail.orEmpty().contains("Rejected"))
    }

    @Test
    fun coordinator_logs_actions_promotes_session_and_signals_current_user() = runTest {
        val logs = DebugLogStore()
        val sessions = AppSessionStore()
        val credentialSignals = FakeCredentialSignalDemoClient()
        val coordinator = AuthDemoCoordinator(
            config = PasskeyDemoConfig(
                endpointBase = "https://example.test",
                rpId = "example.test",
                origin = "https://example.test",
                userHandle = "demo-user",
                userName = "demo@local",
            ),
            debugLogs = logs,
            sessionStore = sessions,
            credentialSignalClient = credentialSignals,
        )

        coordinator.onSignInClicked()
        coordinator.onCeremonyStateChanged(DemoCeremonyState.Success(DemoPasskeyAction.SIGN_IN))

        assertEquals(AppSessionState.SignedIn("demo@local"), sessions.state.value)
        assertTrue(logs.entries.any { it.source == "action" && it.message.contains("Sign In tapped") })
        assertTrue(logs.entries.any { it.source == "flow" && it.message.contains("Sign In success") })
        assertTrue(logs.entries.any { it.source == "signals" && it.message.contains("accepted") })
        assertEquals(1, credentialSignals.currentUserDetailsCalls)
        assertEquals("example.test", credentialSignals.lastRpId?.value)
        assertEquals("ZGVtby11c2Vy", credentialSignals.lastUserId?.value?.encoded())
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
