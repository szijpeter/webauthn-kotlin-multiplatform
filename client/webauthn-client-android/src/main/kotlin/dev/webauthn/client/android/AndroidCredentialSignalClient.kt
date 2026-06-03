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
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import kotlin.coroutines.cancellation.CancellationException
import org.json.JSONArray
import org.json.JSONObject

/**
 * Android Credential Manager Signal API client for provider-side passkey consistency hints.
 *
 * Signal requests do not show UI. A successful result means Credential Manager accepted and
 * dispatched the signal to enabled providers, not that any provider applied the update.
 */
public class AndroidCredentialSignalClient(
    private val context: Context,
    private val credentialManagerFactory: (Context) -> CredentialManager = CredentialManager::create,
) {
    /**
     * Signals the complete set of credential IDs accepted for the given user.
     *
     * Use this after account recovery, credential deletion, or server reconciliation.
     */
    public suspend fun signalAllAcceptedCredentialIds(
        rpId: RpId,
        userId: UserHandle,
        credentialIds: List<CredentialId>,
        origin: String? = null,
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
                origin = origin,
            ),
        )
    }

    /**
     * Signals that the relying party does not recognize a credential ID.
     *
     * Use this after receiving an assertion for a credential that no longer exists server-side.
     */
    public suspend fun signalUnknownCredential(
        rpId: RpId,
        credentialId: CredentialId,
        origin: String? = null,
    ): PasskeyResult<Unit> {
        return signalCredentialState(
            SignalUnknownCredentialRequest(
                requestJson = JSONObject()
                    .put(RP_ID_KEY, rpId.value)
                    .put(CREDENTIAL_ID_KEY, credentialId.value.encoded())
                    .toString(),
                origin = origin,
            ),
        )
    }

    /**
     * Signals the current user name and display name for a server-side account.
     */
    public suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
        origin: String? = null,
    ): PasskeyResult<Unit> {
        return signalCredentialState(
            SignalCurrentUserDetailsRequest(
                requestJson = JSONObject()
                    .put(RP_ID_KEY, rpId.value)
                    .put(USER_ID_KEY, userId.value.encoded())
                    .put(NAME_KEY, name)
                    .put(DISPLAY_NAME_KEY, displayName)
                    .toString(),
                origin = origin,
            ),
        )
    }

    private suspend fun signalCredentialState(request: SignalCredentialStateRequest): PasskeyResult<Unit> {
        @Suppress("TooGenericExceptionCaught")
        return try {
            credentialManagerFactory(context).signalCredentialState(request)
            PasskeyResult.Success(Unit)
        } catch (error: CancellationException) {
            throw error
        } catch (error: IllegalArgumentException) {
            PasskeyResult.Failure(PasskeyClientError.InvalidOptions(error.message ?: "Invalid signal request"))
        } catch (error: SignalCredentialStateException) {
            platformFailure(error, "Credential signal failed")
        } catch (error: SecurityException) {
            platformFailure(error, "Credential signal not permitted")
        } catch (error: Throwable) {
            platformFailure(error, "Credential signal failed")
        }
    }

    private fun platformFailure(error: Throwable, fallbackMessage: String): PasskeyResult.Failure {
        return PasskeyResult.Failure(PasskeyClientError.Platform(error.message ?: fallbackMessage, error))
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
