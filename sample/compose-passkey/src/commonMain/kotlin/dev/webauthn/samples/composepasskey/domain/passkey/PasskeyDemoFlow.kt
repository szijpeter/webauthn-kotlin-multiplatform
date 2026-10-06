package dev.webauthn.samples.composepasskey.domain.passkey

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.samples.composepasskey.PasskeyDemoBuildConfig
import dev.webauthn.samples.composepasskey.data.network.resolveDefaultOrigin
import dev.webauthn.samples.composepasskey.data.network.resolveDefaultRpId
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.model.StatusTone

internal data class PasskeyDemoConfig(
    val endpointBase: String = PasskeyDemoBuildConfig.ENDPOINT_BASE,
    val rpId: String = resolveDefaultRpId(endpointBase, PasskeyDemoBuildConfig.RP_ID),
    val origin: String = resolveDefaultOrigin(rpId, PasskeyDemoBuildConfig.ORIGIN),
    val userHandle: String = PasskeyDemoBuildConfig.USER_ID,
    val userName: String = PasskeyDemoBuildConfig.USER_NAME,
)

internal enum class DemoPasskeyAction { REGISTER, SIGN_IN }

internal sealed interface DemoCeremonyError {
    val message: String

    data class Platform(val error: PasskeyClientError) : DemoCeremonyError {
        override val message: String = error.message
    }

    data class Backend(override val message: String) : DemoCeremonyError

    data class Rejected(override val message: String) : DemoCeremonyError

    data object AlreadyInProgress : DemoCeremonyError {
        override val message: String = "Another ceremony is already in progress."
    }
}

internal sealed interface DemoCeremonyState {
    data object Idle : DemoCeremonyState

    data class InProgress(
        val action: DemoPasskeyAction,
        val phase: PasskeyPhase,
    ) : DemoCeremonyState

    data class Success(val action: DemoPasskeyAction) : DemoCeremonyState

    data class Failure(
        val action: DemoPasskeyAction,
        val error: DemoCeremonyError,
    ) : DemoCeremonyState
}

internal fun areCeremonyActionsEnabled(uiState: DemoCeremonyState): Boolean {
    return uiState !is DemoCeremonyState.InProgress
}

internal fun DemoCeremonyState.toDemoStatus(): PasskeyDemoStatus {
    return when (this) {
        DemoCeremonyState.Idle -> PasskeyDemoStatus(
            tone = StatusTone.IDLE,
            headline = "Ready",
            detail = "Run Register or Sign In to exercise the end-to-end passkey flow.",
        )

        is DemoCeremonyState.InProgress -> PasskeyDemoStatus(
            tone = StatusTone.WORKING,
            headline = "${action.label()} in progress",
            detail = when (phase) {
                PasskeyPhase.STARTING -> "Loading server options."
                PasskeyPhase.PLATFORM_PROMPT -> "Waiting for the platform passkey prompt."
                PasskeyPhase.FINISHING -> "Verifying the passkey response."
            },
        )

        is DemoCeremonyState.Success -> PasskeyDemoStatus(
            tone = StatusTone.SUCCESS,
            headline = "${action.label()} complete",
            detail = when (action) {
                DemoPasskeyAction.REGISTER -> "Passkey created. Run Sign In to verify the round trip."
                DemoPasskeyAction.SIGN_IN -> "Authenticated successfully. Opening the extension demo."
            },
        )

        is DemoCeremonyState.Failure -> PasskeyDemoStatus(
            tone = if (error is DemoCeremonyError.Platform && error.error is PasskeyClientError.UserCancelled) {
                StatusTone.WARNING
            } else {
                StatusTone.ERROR
            },
            headline = error.label(),
            detail = error.userGuidance(),
        )
    }
}

internal data class DemoTransitionEvent(
    val level: DebugLogLevel,
    val message: String,
)

internal fun demoTransitionEvent(
    previous: DemoCeremonyState,
    current: DemoCeremonyState,
): DemoTransitionEvent? {
    if (current is DemoCeremonyState.InProgress && previous != current) {
        return DemoTransitionEvent(DebugLogLevel.INFO, "${current.action.label()} ${current.phase.logLabel()}")
    }
    if (current is DemoCeremonyState.Success && previous != current) {
        return DemoTransitionEvent(DebugLogLevel.INFO, "${current.action.label()} success")
    }
    if (current is DemoCeremonyState.Failure && previous != current) {
        return DemoTransitionEvent(
            level = if (current.error is DemoCeremonyError.Platform &&
                current.error.error is PasskeyClientError.UserCancelled
            ) DebugLogLevel.WARN else DebugLogLevel.ERROR,
            message = "${current.action.label()} failed [${current.error.label()}]",
        )
    }
    return null
}

private fun DemoCeremonyError.label(): String = when (this) {
    is DemoCeremonyError.Platform -> when (error) {
        is PasskeyClientError.UserCancelled -> "User Cancelled"
        is PasskeyClientError.NoCredential -> "No Credential"
        is PasskeyClientError.InvalidOptions -> "Invalid Options"
        is PasskeyClientError.Platform -> "Platform"
        is PasskeyClientError.Codec -> "Codec"
    }
    is DemoCeremonyError.Backend -> "Backend"
    is DemoCeremonyError.Rejected -> "Rejected"
    DemoCeremonyError.AlreadyInProgress -> "Already In Progress"
}

private fun DemoPasskeyAction.label(): String = when (this) {
    DemoPasskeyAction.REGISTER -> "Register"
    DemoPasskeyAction.SIGN_IN -> "Sign In"
}

private fun PasskeyPhase.logLabel(): String = when (this) {
    PasskeyPhase.STARTING -> "starting"
    PasskeyPhase.PLATFORM_PROMPT -> "platform_prompt"
    PasskeyPhase.FINISHING -> "finishing"
}

internal fun DemoCeremonyError.userGuidance(): String = when (this) {
    is DemoCeremonyError.Platform -> when (error) {
        is PasskeyClientError.UserCancelled -> "No changes were made. Choose Register or Sign In when you are ready."
        is PasskeyClientError.NoCredential ->
            "No matching passkey was found. Use the account that owns it, or choose Register."
        is PasskeyClientError.InvalidOptions, is PasskeyClientError.Codec ->
            "Check the relying party and server configuration before starting a new attempt."
        is PasskeyClientError.Platform ->
            "Your passkey provider could not complete the request. Check its availability, then start a new attempt."
    }
    is DemoCeremonyError.Backend -> "Check the server configuration and connection, then start a new attempt."
    is DemoCeremonyError.Rejected ->
        "The server did not accept the response. Start a new sign-in request; " +
            "contact the server administrator if this continues."
    DemoCeremonyError.AlreadyInProgress -> "Wait for the current request to finish before starting another."
}
