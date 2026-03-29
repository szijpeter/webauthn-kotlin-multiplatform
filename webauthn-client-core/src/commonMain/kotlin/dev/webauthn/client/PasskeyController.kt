@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.runtime.rethrowCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex

/** Shared registration/authentication ceremony coordinator for app-facing flows. */
public class PasskeyController<RegisterParams, SignInParams>(
    private val passkeyClient: PasskeyClient,
    private val serverClient: PasskeyServerClient<RegisterParams, SignInParams>,
) {
    private val _uiState = MutableStateFlow<PasskeyControllerState>(PasskeyControllerState.Idle)
    private val ceremonyMutex = Mutex()

    /**
     * A flow of the current state of the Passkey Ceremony.
     */
    public val uiState: StateFlow<PasskeyControllerState> = _uiState.asStateFlow()

    /**
     * Resets the controller state to [PasskeyControllerState.Idle].
     */
    public fun resetToIdle() {
        _uiState.value = PasskeyControllerState.Idle
    }

    /**
     * Triggers a full registration ceremony.
     *
     * @param params Client-specific parameters needed by the server to start/finish registration.
     */
    public suspend fun register(params: RegisterParams) {
        runCeremony(
            action = PasskeyAction.REGISTER,
            getOptions = { serverClient.getRegisterOptions(params) },
            extractChallenge = { options -> options.challenge.value.encoded() },
            interactWithPlatform = passkeyClient::createCredential,
            finish = { response, challenge -> serverClient.finishRegister(params, response, challenge) },
        )
    }

    /**
     * Triggers a full authentication ceremony.
     *
     * @param params Client-specific parameters needed by the server to start/finish sign in.
     */
    public suspend fun signIn(params: SignInParams) {
        runCeremony(
            action = PasskeyAction.SIGN_IN,
            getOptions = { serverClient.getSignInOptions(params) },
            extractChallenge = { options -> options.challenge.value.encoded() },
            interactWithPlatform = passkeyClient::getAssertion,
            finish = { response, challenge -> serverClient.finishSignIn(params, response, challenge) },
        )
    }

    @Suppress("CyclomaticComplexMethod", "TooGenericExceptionCaught")
    private suspend fun <OptionsT, ResponseT> runCeremony(
        action: PasskeyAction,
        getOptions: suspend () -> ValidationResult<OptionsT>,
        extractChallenge: (OptionsT) -> String,
        interactWithPlatform: suspend (options: OptionsT) -> PasskeyResult<ResponseT>,
        finish: suspend (response: ResponseT, challengeAsBase64Url: String) -> PasskeyFinishResult,
    ) {
        if (!ceremonyMutex.tryLock()) {
            return
        }

        try {
            emitProgress(action, PasskeyPhase.STARTING)

            val options = when (val result = getOptions()) {
                is ValidationResult.Valid -> result.value
                is ValidationResult.Invalid -> return fail(
                    action,
                    PasskeyClientError.InvalidOptions("Options validation failed: ${result.errorMessage()}"),
                )
            }
            val challenge = extractChallenge(options)

            emitProgress(action, PasskeyPhase.PLATFORM_PROMPT)
            val response = when (val result = interactWithPlatform(options)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> return fail(action, result.error)
            }

            emitProgress(action, PasskeyPhase.FINISHING)
            when (val result = finish(response, challenge)) {
                PasskeyFinishResult.Verified -> _uiState.value = PasskeyControllerState.Success(action)
                is PasskeyFinishResult.Rejected -> {
                    val message = result.message ?: "${action.name} verification was rejected by the server."
                    return fail(action, PasskeyClientError.Transport(message))
                }
            }
        } catch (e: Exception) {
            e.rethrowCancellation()
            val error = when (e) {
                is IllegalArgumentException -> PasskeyClientError.InvalidOptions(e.message ?: "Invalid options")
                else -> PasskeyClientError.Transport(e.message ?: "Server interaction failed", e)
            }
            _uiState.value = PasskeyControllerState.Failure(action, error)
        } finally {
            if (_uiState.value is PasskeyControllerState.InProgress) {
                // If we exit while still in progress, it implies a CancellationException bubbled up
                _uiState.value = PasskeyControllerState.Idle
            }
            ceremonyMutex.unlock()
        }
    }

    private fun emitProgress(action: PasskeyAction, phase: PasskeyPhase) {
        _uiState.value = PasskeyControllerState.InProgress(action, phase)
    }

    private fun fail(action: PasskeyAction, error: PasskeyClientError) {
        _uiState.value = PasskeyControllerState.Failure(action, error)
    }

    private fun ValidationResult.Invalid.errorMessage(): String =
        errors.joinToString("; ") { "${it.field}: ${it.message}" }
}
