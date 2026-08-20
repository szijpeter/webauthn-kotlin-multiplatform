package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPhase
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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasskeyDemoStateTest {
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
    fun coordinator_logs_actions_and_promotes_sign_in_to_app_session() {
        val logs = DebugLogStore()
        val sessions = AppSessionStore()
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
        )

        coordinator.onSignInClicked()
        coordinator.onCeremonyStateChanged(DemoCeremonyState.Success(DemoPasskeyAction.SIGN_IN))

        assertEquals(AppSessionState.SignedIn("demo@local"), sessions.state.value)
        assertTrue(logs.entries.any { it.source == "action" && it.message.contains("Sign In tapped") })
        assertTrue(logs.entries.any { it.source == "flow" && it.message.contains("Sign In success") })
    }
}
