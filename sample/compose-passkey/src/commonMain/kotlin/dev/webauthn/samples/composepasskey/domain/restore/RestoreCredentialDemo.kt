package dev.webauthn.samples.composepasskey.domain.restore

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload

internal interface RestoreCredentialDemoClient {
    val isAvailable: Boolean

    suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean = true,
    ): PasskeyResult<RegistrationResponse>

    suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse>

    suspend fun clearRestoreCredential(): PasskeyResult<Unit>
}

internal class UnsupportedRestoreCredentialDemoClient : RestoreCredentialDemoClient {
    override val isAvailable: Boolean = false

    override suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean,
    ): PasskeyResult<RegistrationResponse> {
        return PasskeyResult.Failure(unsupportedError())
    }

    override suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return PasskeyResult.Failure(unsupportedError())
    }

    override suspend fun clearRestoreCredential(): PasskeyResult<Unit> {
        return PasskeyResult.Failure(unsupportedError())
    }
}

internal sealed interface RestoreCredentialDemoResult {
    data class Success(val message: String) : RestoreCredentialDemoResult
    data class Failure(val message: String) : RestoreCredentialDemoResult
}

internal class RestoreCredentialDemoController(
    private val restoreCredentialClient: RestoreCredentialDemoClient,
    private val serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
) {
    val isAvailable: Boolean
        get() = restoreCredentialClient.isAvailable

    suspend fun createRestoreCredential(config: PasskeyDemoConfig): RestoreCredentialDemoResult {
        return runRestoreOperation {
            val params = config.toRegistrationStartPayload()
            val options = when (val result = serverClient.getRegisterOptions(params)) {
                is ValidationResult.Valid -> result.value
                is ValidationResult.Invalid -> {
                    return@runRestoreOperation failure("Restore key options failed: ${result.errorMessage()}")
                }
            }
            val challenge = options.challenge.value.encoded()
            val response = when (val result = restoreCredentialClient.createRestoreCredential(options)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> return@runRestoreOperation failure(result.error.message)
            }
            when (val result = serverClient.finishRegister(params, response, challenge)) {
                PasskeyFinishResult.Verified -> success("Restore key created and verified by the server.")
                is PasskeyFinishResult.Rejected -> {
                    failure(result.message ?: "Restore key registration was rejected by the server.")
                }
            }
        }
    }

    suspend fun getRestoreCredential(config: PasskeyDemoConfig): RestoreCredentialDemoResult {
        return runRestoreOperation {
            val params = config.toAuthenticationStartPayload()
            val options = when (val result = serverClient.getSignInOptions(params)) {
                is ValidationResult.Valid -> result.value
                is ValidationResult.Invalid -> {
                    return@runRestoreOperation failure("Restore sign-in options failed: ${result.errorMessage()}")
                }
            }
            val challenge = options.challenge.value.encoded()
            val response = when (val result = restoreCredentialClient.getRestoreCredential(options)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> return@runRestoreOperation failure(result.error.message)
            }
            when (val result = serverClient.finishSignIn(params, response, challenge)) {
                PasskeyFinishResult.Verified -> success("Restore credential sign-in verified.")
                is PasskeyFinishResult.Rejected -> {
                    failure(result.message ?: "Restore credential sign-in was rejected by the server.")
                }
            }
        }
    }

    suspend fun clearRestoreCredential(): RestoreCredentialDemoResult {
        return runRestoreOperation {
            when (val result = restoreCredentialClient.clearRestoreCredential()) {
                is PasskeyResult.Success -> success("Restore key cleared.")
                is PasskeyResult.Failure -> failure(result.error.message)
            }
        }
    }

    private suspend fun runRestoreOperation(
        operation: suspend () -> RestoreCredentialDemoResult,
    ): RestoreCredentialDemoResult {
        return runSuspendCatching {
            operation()
        }.getOrElse { error ->
            failure(error.message ?: "Restore credential operation failed.")
        }
    }

    private fun ValidationResult.Invalid.errorMessage(): String {
        return errors.joinToString("; ") { "${it.field}: ${it.message}" }
    }
}

private fun unsupportedError(): PasskeyClientError {
    return PasskeyClientError.Platform("Restore Credentials are only available in the Android sample.")
}

private fun success(message: String): RestoreCredentialDemoResult.Success {
    return RestoreCredentialDemoResult.Success(message)
}

private fun failure(message: String): RestoreCredentialDemoResult.Failure {
    return RestoreCredentialDemoResult.Failure(message)
}
