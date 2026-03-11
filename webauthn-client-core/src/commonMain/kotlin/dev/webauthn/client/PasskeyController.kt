package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex

public enum class PasskeyAction {
    REGISTER,
    SIGN_IN,
}

public enum class PasskeyPhase {
    STARTING,
    PLATFORM_PROMPT,
    FINISHING,
}

public sealed interface PasskeyControllerState {
    public data object Idle : PasskeyControllerState

    public data class InProgress(
        public val action: PasskeyAction,
        public val phase: PasskeyPhase,
    ) : PasskeyControllerState

    public data class Success(
        public val action: PasskeyAction,
    ) : PasskeyControllerState

    public data class Failure(
        public val action: PasskeyAction,
        public val error: PasskeyClientError,
    ) : PasskeyControllerState
}

public interface PasskeyServerClient<RegisterParams, SignInParams> {
    public suspend fun getRegisterOptions(params: RegisterParams): ValidationResult<PublicKeyCredentialCreationOptions>
    public suspend fun finishRegister(params: RegisterParams, response: RegistrationResponse, challengeAsBase64Url: String): Boolean

    public suspend fun getSignInOptions(params: SignInParams): ValidationResult<PublicKeyCredentialRequestOptions>
    public suspend fun finishSignIn(params: SignInParams, response: AuthenticationResponse, challengeAsBase64Url: String): Boolean
}

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
            interactWithPlatform = { options -> passkeyClient.createCredential(options) },
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
            interactWithPlatform = { options -> passkeyClient.getAssertion(options) },
            finish = { response, challenge -> serverClient.finishSignIn(params, response, challenge) },
        )
    }

    @Suppress("MaxLineLength", "TooGenericExceptionCaught")
    private suspend fun <OptionsT, ResponseT> runCeremony(
        action: PasskeyAction,
        getOptions: suspend () -> ValidationResult<OptionsT>,
        extractChallenge: (OptionsT) -> String,
        interactWithPlatform: suspend (options: OptionsT) -> PasskeyResult<ResponseT>,
        finish: suspend (response: ResponseT, challengeAsBase64Url: String) -> Boolean,
    ) {
        if (!ceremonyMutex.tryLock()) {
            return
        }

        try {
            _uiState.value = PasskeyControllerState.InProgress(action, PasskeyPhase.STARTING)

            // 1. Starting (Network)
            val validOptions = when (val optionsResult = getOptions()) {
                is ValidationResult.Valid -> optionsResult.value
                is ValidationResult.Invalid -> {
                    val message = optionsResult.errors.joinToString("; ") { "${it.field}: ${it.message}" }
                    _uiState.value = PasskeyControllerState.Failure(action, PasskeyClientError.InvalidOptions("Options validation failed: $message"))
                    return
                }
            }

            val challengeBase64Url = extractChallenge(validOptions)

            // 2. Platform Prompting
            _uiState.value = PasskeyControllerState.InProgress(action, PasskeyPhase.PLATFORM_PROMPT)
            val platformResponse = when (val result = interactWithPlatform(validOptions)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> {
                    _uiState.value = PasskeyControllerState.Failure(action, result.error)
                    return
                }
            }

            // 3. Finishing (Network)
            _uiState.value = PasskeyControllerState.InProgress(action, PasskeyPhase.FINISHING)
            val isVerified = finish(platformResponse, challengeBase64Url)

            if (!isVerified) {
                _uiState.value = PasskeyControllerState.Failure(action, PasskeyClientError.Transport("${action.name} verification was rejected by the server."))
                return
            }

            // 4. Success
            _uiState.value = PasskeyControllerState.Success(action)

        } catch (e: CancellationException) {
            if (_uiState.value is PasskeyControllerState.InProgress) {
                _uiState.value = PasskeyControllerState.Idle
            }
            throw e
        } catch (e: Exception) {
            val error = when (e) {
                is IllegalArgumentException -> PasskeyClientError.InvalidOptions(e.message ?: "Invalid options")
                else -> PasskeyClientError.Transport(e.message ?: "Server interaction failed", e)
            }
            _uiState.value = PasskeyControllerState.Failure(action, error)
        } finally {
            ceremonyMutex.unlock()
        }
    }
}
