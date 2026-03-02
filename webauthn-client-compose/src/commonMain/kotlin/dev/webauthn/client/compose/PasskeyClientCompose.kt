package dev.webauthn.client.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import kotlinx.coroutines.CancellationException

public enum class PasskeyAction {
    REGISTER,
    SIGN_IN,
}

public enum class PasskeyPhase {
    STARTING,
    PLATFORM_PROMPT,
    FINISHING,
}

public sealed interface PasskeyClientUiState {
    public data object Idle : PasskeyClientUiState

    public data class InProgress(
        public val action: PasskeyAction,
        public val phase: PasskeyPhase,
    ) : PasskeyClientUiState

    public data class Success(
        public val action: PasskeyAction,
    ) : PasskeyClientUiState

    public data class Failure(
        public val action: PasskeyAction,
        public val error: PasskeyClientError,
    ) : PasskeyClientUiState
}

public class PasskeyClientState(
    private val passkeyClient: PasskeyClient,
) {
    public var uiState: PasskeyClientUiState by mutableStateOf(PasskeyClientUiState.Idle)
        private set

    public fun begin(action: PasskeyAction) {
        when (uiState) {
            PasskeyClientUiState.Idle,
            is PasskeyClientUiState.Success,
            is PasskeyClientUiState.Failure,
            -> uiState = PasskeyClientUiState.InProgress(action = action, phase = PasskeyPhase.STARTING)

            is PasskeyClientUiState.InProgress -> invalidTransition(
                action = "begin($action)",
                expected = "Idle/Success/Failure",
            )
        }
    }

    public fun setPhase(
        action: PasskeyAction,
        phase: PasskeyPhase,
    ) {
        val inProgress = requireInProgressState(action = action, actionName = "setPhase($action, $phase)")
        uiState = inProgress.copy(phase = phase)
    }

    public fun finishSuccess(action: PasskeyAction) {
        requireInProgressState(action = action, actionName = "finishSuccess($action)")
        uiState = PasskeyClientUiState.Success(action = action)
    }

    public fun finishFailure(
        action: PasskeyAction,
        error: PasskeyClientError,
    ) {
        requireInProgressState(action = action, actionName = "finishFailure($action)")
        uiState = PasskeyClientUiState.Failure(action = action, error = error)
    }

    public fun resetToIdle() {
        uiState = PasskeyClientUiState.Idle
    }

    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        requireInProgressState(action = PasskeyAction.REGISTER, actionName = "createCredential")
        return runClientCall { passkeyClient.createCredential(options) }
    }

    public suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        requireInProgressState(action = PasskeyAction.SIGN_IN, actionName = "getAssertion")
        return runClientCall { passkeyClient.getAssertion(options) }
    }

    private suspend fun <T> runClientCall(
        call: suspend () -> PasskeyResult<T>,
    ): PasskeyResult<T> {
        return try {
            call()
        } catch (throwable: Throwable) {
            if (throwable is CancellationException) {
                throw throwable
            }
            PasskeyResult.Failure(throwable.toPasskeyClientError())
        }
    }

    private fun requireInProgressState(
        action: PasskeyAction,
        actionName: String,
    ): PasskeyClientUiState.InProgress {
        val currentState = uiState
        return if (currentState is PasskeyClientUiState.InProgress && currentState.action == action) {
            currentState
        } else {
            invalidTransition(action = actionName, expected = "InProgress($action, ...)")
        }
    }

    private fun invalidTransition(
        action: String,
        expected: String,
    ): Nothing {
        throw IllegalStateException(
            "Invalid PasskeyClientState transition: action=$action expected=$expected actual=$uiState",
        )
    }
}

@Composable
public fun rememberPasskeyClientState(
    passkeyClient: PasskeyClient = rememberPasskeyClient(),
): PasskeyClientState {
    return remember(passkeyClient) { PasskeyClientState(passkeyClient) }
}

@Composable
public expect fun rememberPasskeyClient(): PasskeyClient

private fun Throwable.toPasskeyClientError(): PasskeyClientError {
    val message = message?.takeIf { it.isNotBlank() } ?: "Passkey operation failed."
    return PasskeyClientError.Platform(message)
}
