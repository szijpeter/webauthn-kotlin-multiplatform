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

public enum class PasskeyOperation {
    CREATE_CREDENTIAL,
    GET_ASSERTION,
}

public data class PasskeyClientUiState(
    public val isBusy: Boolean = false,
    public val activeOperation: PasskeyOperation? = null,
    public val lastError: PasskeyClientError? = null,
    public val lastSuccess: PasskeyOperation? = null,
)

public class PasskeyClientState(
    private val passkeyClient: PasskeyClient,
) {
    public var uiState: PasskeyClientUiState by mutableStateOf(PasskeyClientUiState())
        private set

    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        return runOperation(
            operation = PasskeyOperation.CREATE_CREDENTIAL,
            execute = { passkeyClient.createCredential(options) },
        )
    }

    public suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return runOperation(
            operation = PasskeyOperation.GET_ASSERTION,
            execute = { passkeyClient.getAssertion(options) },
        )
    }

    private suspend fun <T> runOperation(
        operation: PasskeyOperation,
        execute: suspend () -> PasskeyResult<T>,
    ): PasskeyResult<T> {
        uiState = uiState.copy(
            isBusy = true,
            activeOperation = operation,
            lastError = null,
        )

        val result = execute()

        uiState = when (result) {
            is PasskeyResult.Success -> {
                uiState.copy(
                    isBusy = false,
                    activeOperation = null,
                    lastSuccess = operation,
                    lastError = null,
                )
            }

            is PasskeyResult.Failure -> {
                uiState.copy(
                    isBusy = false,
                    activeOperation = null,
                    lastError = result.error,
                )
            }
        }

        return result
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
