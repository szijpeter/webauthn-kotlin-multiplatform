package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.SignalAllAcceptedCredentialIdsRequest
import androidx.credentials.SignalCredentialStateRequest
import androidx.credentials.SignalCurrentUserDetailsRequest
import androidx.credentials.SignalUnknownCredentialRequest
import androidx.credentials.exceptions.publickeycredential.SignalCredentialStateException
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.runtime.suspendCatchingNonCancellation
import org.json.JSONArray
import org.json.JSONObject

/**
 * Android Credential Manager Signal API client for provider-side passkey consistency hints.
 *
 * Signal requests do not show UI. Success means Credential Manager accepted and dispatched the
 * signal to enabled providers; it does not prove that a provider applied the update.
 */
public class AndroidCredentialSignalClient(
    private val context: Context,
    private val credentialManagerFactory: (Context) -> CredentialManager = CredentialManager::create,
) {
    /**
     * Signals the complete set of credential IDs accepted for the given user.
     *
     * [origin] is only for browsers or privileged apps acting for another application. Ordinary
     * apps must leave it `null`; on Android 14+ a non-null value also requires
     * `android.permission.CREDENTIAL_MANAGER_SET_ORIGIN`.
     */
    public suspend fun signalAllAcceptedCredentialIds(
        rpId: RpId,
        userId: UserHandle,
        credentialIds: List<CredentialId>,
        origin: Origin? = null,
    ): PasskeyResult<Unit> {
        return signalCredentialState(
            SignalAllAcceptedCredentialIdsRequest(
                requestJson = JSONObject()
                    .put(RP_ID_KEY, rpId.value)
                    .put(USER_ID_KEY, userId.value.encoded())
                    .put(
                        ACCEPTED_CREDENTIAL_IDS_KEY,
                        JSONArray(credentialIds.map { it.value.encoded() }),
                    )
                    .toString(),
                origin = origin?.value,
            ),
        )
    }

    /**
     * Signals that the relying party does not recognize a credential ID.
     *
     * [origin] is only for browsers or privileged apps acting for another application. Ordinary
     * apps must leave it `null`; on Android 14+ a non-null value also requires
     * `android.permission.CREDENTIAL_MANAGER_SET_ORIGIN`.
     */
    public suspend fun signalUnknownCredential(
        rpId: RpId,
        credentialId: CredentialId,
        origin: Origin? = null,
    ): PasskeyResult<Unit> {
        return signalCredentialState(
            SignalUnknownCredentialRequest(
                requestJson = JSONObject()
                    .put(RP_ID_KEY, rpId.value)
                    .put(CREDENTIAL_ID_KEY, credentialId.value.encoded())
                    .toString(),
                origin = origin?.value,
            ),
        )
    }

    /**
     * Signals the current user name and display name for a server-side account.
     *
     * [origin] is only for browsers or privileged apps acting for another application. Ordinary
     * apps must leave it `null`; on Android 14+ a non-null value also requires
     * `android.permission.CREDENTIAL_MANAGER_SET_ORIGIN`.
     */
    public suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
        origin: Origin? = null,
    ): PasskeyResult<Unit> {
        return signalCredentialState(
            SignalCurrentUserDetailsRequest(
                requestJson = JSONObject()
                    .put(RP_ID_KEY, rpId.value)
                    .put(USER_ID_KEY, userId.value.encoded())
                    .put(NAME_KEY, name)
                    .put(DISPLAY_NAME_KEY, displayName)
                    .toString(),
                origin = origin?.value,
            ),
        )
    }

    private suspend fun signalCredentialState(request: SignalCredentialStateRequest): PasskeyResult<Unit> {
        return suspendCatchingNonCancellation {
            credentialManagerFactory(context).signalCredentialState(request)
        }.fold(
            onSuccess = { PasskeyResult.Success(Unit) },
            onFailure = { PasskeyResult.Failure(mapSignalError(it)) },
        )
    }

    private fun mapSignalError(error: Throwable): PasskeyClientError = when (error) {
        is IllegalArgumentException -> PasskeyClientError.InvalidOptions(
            error.message ?: "Invalid credential signal request",
        )
        is SignalCredentialStateException -> PasskeyClientError.Platform(
            error.message ?: "Credential signal failed",
        )
        is SecurityException -> PasskeyClientError.Platform(
            error.message ?: "Credential signal not permitted",
        )
        else -> PasskeyClientError.Platform(error.message ?: "Credential signal failed")
    }

    private companion object {
        const val RP_ID_KEY = "rpId"
        const val USER_ID_KEY = "userId"
        const val ACCEPTED_CREDENTIAL_IDS_KEY = "allAcceptedCredentialIds"
        const val CREDENTIAL_ID_KEY = "credentialId"
        const val NAME_KEY = "name"
        const val DISPLAY_NAME_KEY = "displayName"
    }
}
