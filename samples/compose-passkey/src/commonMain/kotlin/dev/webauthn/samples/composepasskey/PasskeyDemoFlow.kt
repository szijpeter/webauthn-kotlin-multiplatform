package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.model.StatusTone

public data class PasskeyDemoConfig(
    public val endpointBase: String = PasskeyDemoBuildConfig.ENDPOINT_BASE,
    public val rpId: String = resolveDefaultRpId(
        endpointBase = PasskeyDemoBuildConfig.ENDPOINT_BASE,
        configuredRpId = PasskeyDemoBuildConfig.RP_ID,
    ),
    public val origin: String = resolveDefaultOrigin(
        rpId = rpId,
        configuredOrigin = PasskeyDemoBuildConfig.ORIGIN,
    ),
    public val userHandle: String = PasskeyDemoBuildConfig.USER_ID,
    public val userName: String = PasskeyDemoBuildConfig.USER_NAME,
)

internal fun areCeremonyActionsEnabled(uiState: PasskeyControllerState): Boolean {
    return uiState !is PasskeyControllerState.InProgress
}

internal fun PasskeyControllerState.toStatusPresentation(): PasskeyDemoStatus {
    return when (this) {
        PasskeyControllerState.Idle -> PasskeyDemoStatus(
            tone = StatusTone.IDLE,
            headline = "Ready",
            detail = "Run Register or Sign In to exercise the E2E flow.",
        )

        is PasskeyControllerState.InProgress -> PasskeyDemoStatus(
            tone = StatusTone.WORKING,
            headline = when (action) {
                PasskeyAction.REGISTER -> "Register in progress"
                PasskeyAction.SIGN_IN -> "Sign In in progress"
            },
            detail = when (phase) {
                PasskeyPhase.STARTING -> "Loading options."
                PasskeyPhase.PLATFORM_PROMPT -> "Waiting for passkey prompt."
                PasskeyPhase.FINISHING -> "Verifying response."
            },
        )

        is PasskeyControllerState.Success -> PasskeyDemoStatus(
            tone = StatusTone.SUCCESS,
            headline = when (action) {
                PasskeyAction.REGISTER -> "Register complete"
                PasskeyAction.SIGN_IN -> "Sign In complete"
            },
        )

        is PasskeyControllerState.Failure -> {
            val category = error.toCategory()
            PasskeyDemoStatus(
                tone = if (category == PasskeyDemoErrorCategory.USER_CANCELLED) StatusTone.WARNING else StatusTone.ERROR,
                headline = category.label,
                detail = "[${category.label}] ${error.message.withProviderDependencyHint()}",
            )
        }
    }
}

internal data class ControllerTransitionLog(
    val level: DebugLogLevel,
    val message: String,
)

internal fun controllerTransitionLog(
    previous: PasskeyControllerState,
    current: PasskeyControllerState,
): ControllerTransitionLog? {
    if (current is PasskeyControllerState.InProgress) {
        val changed =
            previous !is PasskeyControllerState.InProgress ||
                previous.action != current.action ||
                previous.phase != current.phase
        if (changed) {
            return ControllerTransitionLog(
                level = DebugLogLevel.INFO,
                message = "${current.action.label()} ${current.phase.logLabel()}",
            )
        }
    }

    if (current is PasskeyControllerState.Success && previous != current) {
        return ControllerTransitionLog(
            level = DebugLogLevel.INFO,
            message = "${current.action.label()} success",
        )
    }

    if (current is PasskeyControllerState.Failure && previous != current) {
        val category = current.error.toCategory()
        return ControllerTransitionLog(
            level = if (category == PasskeyDemoErrorCategory.USER_CANCELLED) DebugLogLevel.WARN else DebugLogLevel.ERROR,
            message = "${current.action.label()} failed [${category.label}] ${current.error.message.withProviderDependencyHint()}",
        )
    }

    return null
}

private enum class PasskeyDemoErrorCategory(public val label: String) {
    INVALID_OPTIONS("Invalid Options"),
    USER_CANCELLED("User Cancelled"),
    PLATFORM("Platform"),
    TRANSPORT("Transport"),
}

private fun PasskeyClientError.toCategory(): PasskeyDemoErrorCategory {
    return when (this) {
        is PasskeyClientError.InvalidOptions -> PasskeyDemoErrorCategory.INVALID_OPTIONS
        is PasskeyClientError.UserCancelled -> PasskeyDemoErrorCategory.USER_CANCELLED
        is PasskeyClientError.Platform -> PasskeyDemoErrorCategory.PLATFORM
        is PasskeyClientError.Transport -> PasskeyDemoErrorCategory.TRANSPORT
    }
}

private fun PasskeyAction.label(): String {
    return when (this) {
        PasskeyAction.REGISTER -> "Register"
        PasskeyAction.SIGN_IN -> "Sign In"
    }
}

private fun PasskeyPhase.logLabel(): String {
    return when (this) {
        PasskeyPhase.STARTING -> "starting"
        PasskeyPhase.PLATFORM_PROMPT -> "platform_prompt"
        PasskeyPhase.FINISHING -> "finishing"
    }
}

private fun String.withProviderDependencyHint(): String {
    val lowered = lowercase()
    return if (lowered.contains("no provider dependencies found")) {
        "$this. Add androidx.credentials:credentials-play-services-auth and use a Google Play-enabled emulator/device."
    } else {
        this
    }
}
