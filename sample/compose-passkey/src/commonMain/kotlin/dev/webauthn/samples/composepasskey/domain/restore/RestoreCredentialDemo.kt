package dev.webauthn.samples.composepasskey.domain.restore

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload

internal interface RestoreCredentialDemoClient {
    val isAvailable: Boolean

    suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean = true,
    ): PasskeyResult<RawRegistrationResponse>

    suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<RawAuthenticationResponse>

    suspend fun clearRestoreCredential(): PasskeyResult<Unit>
}

internal class UnsupportedRestoreCredentialDemoClient : RestoreCredentialDemoClient {
    override val isAvailable: Boolean = false

    override suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean,
    ): PasskeyResult<RawRegistrationResponse> = PasskeyResult.Failure(unsupportedError())

    override suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<RawAuthenticationResponse> = PasskeyResult.Failure(unsupportedError())

    override suspend fun clearRestoreCredential(): PasskeyResult<Unit> =
        PasskeyResult.Failure(unsupportedError())
}

internal sealed interface RestoreCredentialDemoResult {
    data class Success(val message: String) : RestoreCredentialDemoResult
    data class Failure(val message: String) : RestoreCredentialDemoResult
}

internal class RestoreCredentialDemoController(
    private val restoreCredentialClient: RestoreCredentialDemoClient,
    private val backend: DemoPasskeyBackend,
) {
    val isAvailable: Boolean
        get() = restoreCredentialClient.isAvailable

    suspend fun createRestoreCredential(config: PasskeyDemoConfig): RestoreCredentialDemoResult {
        return runRestoreOperation {
            val start = backend.registration.start(config.toRegistrationStartPayload())
            val response = when (val result = restoreCredentialClient.createRestoreCredential(start.options)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> return@runRestoreOperation failure(result.error.message)
            }
            val finishResult = runSuspendCatching {
                backend.registration.finish(start.state, response)
            }.getOrElse { error ->
                return@runRestoreOperation rejectAndClearRestoreCredential(
                    error.message ?: "Restore key registration failed.",
                )
            }
            when (finishResult) {
                DefaultPasskeyFinishResult.Verified -> success("Restore key created and verified by the server.")
                is DefaultPasskeyFinishResult.Rejected -> rejectAndClearRestoreCredential(
                    finishResult.message ?: "Restore key registration was rejected by the server.",
                )
            }
        }
    }

    suspend fun getRestoreCredential(config: PasskeyDemoConfig): RestoreCredentialDemoResult {
        return runRestoreOperation {
            val start = backend.authentication.start(config.toAuthenticationStartPayload())
            val response = when (val result = restoreCredentialClient.getRestoreCredential(start.options)) {
                is PasskeyResult.Success -> result.value
                is PasskeyResult.Failure -> return@runRestoreOperation failure(result.error.message)
            }
            when (val result = backend.authentication.finish(start.state, response)) {
                DefaultPasskeyFinishResult.Verified -> success("Restore credential sign-in verified.")
                is DefaultPasskeyFinishResult.Rejected -> failure(
                    result.message ?: "Restore credential sign-in was rejected by the server.",
                )
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

    private suspend fun rejectAndClearRestoreCredential(message: String): RestoreCredentialDemoResult {
        val cleanup = runSuspendCatching {
            restoreCredentialClient.clearRestoreCredential()
        }.getOrElse { error ->
            return failure("$message Restore-key cleanup also failed: ${error.message ?: "unknown error"}")
        }
        return when (cleanup) {
            is PasskeyResult.Success -> failure(message)
            is PasskeyResult.Failure -> failure(
                "$message Restore-key cleanup also failed: ${cleanup.error.message}",
            )
        }
    }

    private suspend fun runRestoreOperation(
        operation: suspend () -> RestoreCredentialDemoResult,
    ): RestoreCredentialDemoResult {
        return runSuspendCatching { operation() }.getOrElse { error ->
            failure(error.message ?: "Restore credential operation failed.")
        }
    }
}

private fun unsupportedError(): PasskeyClientError =
    PasskeyClientError.Platform("Restore Credentials are only available in the Android sample.")

private fun success(message: String): RestoreCredentialDemoResult.Success =
    RestoreCredentialDemoResult.Success(message)

private fun failure(message: String): RestoreCredentialDemoResult.Failure =
    RestoreCredentialDemoResult.Failure(message)
