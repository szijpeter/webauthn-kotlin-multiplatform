package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoCeremonyState
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.domain.passkey.ceremonyTransitionEvent
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasskeyDemoFlowTest {
    @Test
    fun request_payloads_normalize_plaintext_user_handle_to_base64url() {
        val config = validDemoConfig()
        val expected = Base64UrlBytes.fromBytes("demo-user-1".encodeToByteArray()).encoded()

        assertEquals(expected, config.toRegistrationStartPayload().userHandle)
        assertEquals("required", config.toRegistrationStartPayload().residentKey)
        assertEquals(null, config.toAuthenticationStartPayload().userName)
    }

    @Test
    fun caller_owned_state_disables_actions_only_while_a_ceremony_runs() {
        assertTrue(areCeremonyActionsEnabled(PasskeyDemoCeremonyState.Idle))
        assertFalse(
            areCeremonyActionsEnabled(
                PasskeyDemoCeremonyState.InProgress(PasskeyAction.REGISTER, PasskeyPhase.STARTING),
            ),
        )
        assertTrue(areCeremonyActionsEnabled(PasskeyDemoCeremonyState.Success(PasskeyAction.SIGN_IN)))
    }

    @Test
    fun caller_owned_state_logs_start_success_and_cancellation() {
        val started = ceremonyTransitionEvent(
            previous = PasskeyDemoCeremonyState.Idle,
            current = PasskeyDemoCeremonyState.InProgress(PasskeyAction.REGISTER, PasskeyPhase.STARTING),
        )
        val completed = ceremonyTransitionEvent(
            previous = PasskeyDemoCeremonyState.InProgress(PasskeyAction.REGISTER, PasskeyPhase.FINISHING),
            current = PasskeyDemoCeremonyState.Success(PasskeyAction.REGISTER),
        )
        val cancelled = ceremonyTransitionEvent(
            previous = PasskeyDemoCeremonyState.InProgress(PasskeyAction.SIGN_IN, PasskeyPhase.PLATFORM_PROMPT),
            current = PasskeyDemoCeremonyState.Failure(
                PasskeyAction.SIGN_IN,
                PasskeyClientError.UserCancelled("cancelled"),
            ),
        )

        assertEquals(DebugLogLevel.INFO, started?.level)
        assertTrue(started?.message.orEmpty().contains("starting"))
        assertEquals(DebugLogLevel.INFO, completed?.level)
        assertTrue(completed?.message.orEmpty().contains("success"))
        assertEquals(DebugLogLevel.WARN, cancelled?.level)
        assertTrue(cancelled?.message.orEmpty().contains("failed"))
    }
}

private fun validDemoConfig(): PasskeyDemoConfig = PasskeyDemoConfig(
    endpointBase = "https://example.test",
    rpId = "example.test",
    origin = "https://example.test",
    userHandle = "demo-user-1",
    userName = "demo@local",
)
