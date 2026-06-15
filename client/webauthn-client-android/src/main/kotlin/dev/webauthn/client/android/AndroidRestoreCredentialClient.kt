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
import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyJsonMapper
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.decodeAuthenticationResponseOrThrowPlatform
import dev.webauthn.client.decodeRegistrationResponseOrThrowPlatform
import dev.webauthn.client.encodeAssertionOptionsOrThrowInvalid
import dev.webauthn.client.encodeCreationOptionsOrThrowInvalid
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import kotlin.coroutines.cancellation.CancellationException

/**
 * Android Credential Manager Restore Credentials client.
 *
 * Restore credentials are system-managed restore keys. They should be created after a user signs
 * in, retrieved during app-data restore or first launch, and cleared when the user signs out.
 */
public class AndroidRestoreCredentialClient(
    private val context: Context,
    private val credentialManagerFactory: (Context) -> CredentialManager = CredentialManager::create,
    private val jsonMapper: PasskeyJsonMapper = KotlinxPasskeyJsonMapper(),
) {
    /**
     * Creates a restore credential from WebAuthn creation options.
     *
     * Keep [isCloudBackupEnabled] enabled unless your app intentionally wants a local-only restore
     * key. Local-only restore keys are not available when users restore from cloud backup.
     */
    public suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean = true,
    ): PasskeyResult<RegistrationResponse> {
        return runRestoreOperation {
            val requestJson = jsonMapper.encodeCreationOptionsOrThrowInvalid(options)
            val response = credentialManagerFactory(context).createCredential(
                context = context,
                request = CreateRestoreCredentialRequest(
                    requestJson = requestJson,
                    isCloudBackupEnabled = isCloudBackupEnabled,
                ),
            )
            val responseJson = requireCreateRestoreCredentialResponse(response).responseJson
            jsonMapper.decodeRegistrationResponseOrThrowPlatform(responseJson)
        }
    }

    /**
     * Gets a restore credential from WebAuthn request options.
     *
     * AndroidX sends restore credential requests as passive authentication and overrides user
     * verification to discouraged.
     */
    public suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return runRestoreOperation {
            val requestJson = jsonMapper.encodeAssertionOptionsOrThrowInvalid(options)
            val response = credentialManagerFactory(context).getCredential(
                context = context,
                request = GetCredentialRequest(listOf(GetRestoreCredentialOption(requestJson))),
            )
            val responseJson = requireRestoreCredential(response).authenticationResponseJson
            jsonMapper.decodeAuthenticationResponseOrThrowPlatform(responseJson)
        }
    }

    /**
     * Deletes any stored restore credential for the app.
     *
     * Call this when the user signs out so the next app open requires an explicit sign-in.
     */
    public suspend fun clearRestoreCredential(): PasskeyResult<Unit> {
        return runRestoreOperation {
            credentialManagerFactory(context).clearCredentialState(
                ClearCredentialStateRequest(ClearCredentialStateRequest.TYPE_CLEAR_RESTORE_CREDENTIAL),
            )
        }
    }

    private suspend fun <T> runRestoreOperation(operation: suspend () -> T): PasskeyResult<T> {
        @Suppress("TooGenericExceptionCaught")
        return try {
            PasskeyResult.Success(operation())
        } catch (error: CancellationException) {
            throw error
        } catch (error: IllegalArgumentException) {
            invalidOptionsFailure(error)
        } catch (error: CreateCredentialCancellationException) {
            userCancelledFailure(error, "Restore credential creation cancelled")
        } catch (error: GetCredentialCancellationException) {
            userCancelledFailure(error, "Restore credential retrieval cancelled")
        } catch (error: NoCredentialException) {
            platformFailure(error, "No restore credential found")
        } catch (error: Throwable) {
            platformFailure(error, "Restore credential operation failed")
        }
    }

    private fun invalidOptionsFailure(error: Throwable): PasskeyResult.Failure {
        return PasskeyResult.Failure(
            PasskeyClientError.InvalidOptions(error.message ?: "Invalid restore credential request"),
        )
    }

    private fun userCancelledFailure(error: Throwable, fallbackMessage: String): PasskeyResult.Failure {
        return PasskeyResult.Failure(PasskeyClientError.UserCancelled(error.message ?: fallbackMessage))
    }

    private fun platformFailure(error: Throwable, fallbackMessage: String): PasskeyResult.Failure {
        return PasskeyResult.Failure(PasskeyClientError.Platform(error.message ?: fallbackMessage, error))
    }

    private fun requireCreateRestoreCredentialResponse(
        response: CreateCredentialResponse,
    ): CreateRestoreCredentialResponse {
        return response as? CreateRestoreCredentialResponse
            ?: throw IllegalStateException("Unexpected response type: ${response::class.simpleName}")
    }

    private fun requireRestoreCredential(response: GetCredentialResponse): RestoreCredential {
        val credential = response.credential
        return credential as? RestoreCredential
            ?: throw IllegalStateException("Unexpected credential type: ${credential::class.simpleName}")
    }
}
