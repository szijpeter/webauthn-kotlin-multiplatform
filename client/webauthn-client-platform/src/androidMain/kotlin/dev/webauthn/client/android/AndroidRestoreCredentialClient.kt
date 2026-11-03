package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreateRestoreCredentialRequest
import androidx.credentials.CreateRestoreCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetRestoreCredentialOption
import androidx.credentials.RestoreCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.restorecredential.CreateRestoreCredentialDomException
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.platform.PasskeyCodecException
import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.runtime.suspendCatchingNonCancellation

/**
 * Android Credential Manager Restore Credentials client.
 *
 * Restore credentials are system-managed restore keys. Create one after a user signs in, retrieve
 * it during app-data restore or first launch, and clear it when the user signs out.
 *
 * The caller supplies the JSON codec so this platform artifact remains implementation-neutral.
 */
public class AndroidRestoreCredentialClient(
    private val context: Context,
    private val codec: WebAuthnJsonCodec,
    private val credentialManagerFactory: (Context) -> CredentialManager = CredentialManager::create,
) {
    /**
     * Creates a restore credential from WebAuthn creation options.
     *
     * Keep [isCloudBackupEnabled] enabled unless the application intentionally wants a local-only
     * restore key. Local-only restore keys are unavailable after a cloud restore.
     */
    public suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean = true,
    ): PasskeyResult<RawRegistrationResponse> {
        return runRestoreOperation {
            val requestJson = runCodecOperation("Failed to encode restore credential options") {
                codec.encodeCreationOptions(options)
            }
            val response = credentialManagerFactory(context).createCredential(
                context = context,
                request = CreateRestoreCredentialRequest(
                    requestJson = requestJson,
                    isCloudBackupEnabled = isCloudBackupEnabled,
                ),
            )
            val responseJson = requireCreateRestoreCredentialResponse(response).responseJson
            runCodecOperation("Failed to decode restore registration response") {
                codec.decodeRegistrationResponse(responseJson)
                    .toPlatformValue("Failed to parse restore registration response JSON")
            }
        }
    }

    /**
     * Gets a restore credential from WebAuthn request options.
     *
     * Credential Manager sends restore credential requests as passive authentication and overrides
     * user verification to discouraged.
     */
    public suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<RawAuthenticationResponse> {
        return runRestoreOperation {
            val requestJson = runCodecOperation("Failed to encode restore assertion options") {
                codec.encodeRequestOptions(options)
            }
            val response = credentialManagerFactory(context).getCredential(
                context = context,
                request = GetCredentialRequest(listOf(GetRestoreCredentialOption(requestJson))),
            )
            val responseJson = requireRestoreCredential(response).authenticationResponseJson
            runCodecOperation("Failed to decode restore authentication response") {
                codec.decodeAuthenticationResponse(responseJson)
                    .toPlatformValue("Failed to parse restore authentication response JSON")
            }
        }
    }

    /** Clears any stored restore credential for the application. Call this when the user signs out. */
    public suspend fun clearRestoreCredential(): PasskeyResult<Unit> {
        return runRestoreOperation {
            credentialManagerFactory(context).clearCredentialState(
                ClearCredentialStateRequest(ClearCredentialStateRequest.TYPE_CLEAR_RESTORE_CREDENTIAL),
            )
        }
    }

    private suspend fun <T> runRestoreOperation(operation: suspend () -> T): PasskeyResult<T> {
        return suspendCatchingNonCancellation(operation).fold(
            onSuccess = { PasskeyResult.Success(it) },
            onFailure = { PasskeyResult.Failure(mapRestoreError(it)) },
        )
    }

    private fun mapRestoreError(error: Throwable): PasskeyClientError = when (error) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled(
            error.message ?: "Restore credential operation cancelled",
        )
        is NoCredentialException -> PasskeyClientError.NoCredential("No restore credential found")
        is PasskeyCodecException -> PasskeyClientError.Codec(
            error.message ?: "Restore credential codec failure",
        )
        is CreateRestoreCredentialDomException -> PasskeyClientError.InvalidOptions(
            error.message ?: "Invalid restore credential request",
        )
        is IllegalArgumentException -> PasskeyClientError.InvalidOptions(
            error.message ?: "Invalid restore credential request",
        )
        else -> PasskeyClientError.Platform(
            error.message ?: "Restore credential operation failed",
        )
    }

    private fun requireCreateRestoreCredentialResponse(
        response: CreateCredentialResponse,
    ): CreateRestoreCredentialResponse {
        return response as? CreateRestoreCredentialResponse
            ?: throw IllegalStateException("Unexpected response type: ${response::class.simpleName}")
    }

    private fun requireRestoreCredential(response: GetCredentialResponse): RestoreCredential {
        return response.credential as? RestoreCredential
            ?: throw IllegalStateException("Unexpected credential type: ${response.credential::class.simpleName}")
    }
}
