package dev.webauthn.samples.composepasskey.domain.signals

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Swift-implemented bridge for iOS credential-manager sync reports.
 *
 * Kotlin/Native does not currently expose Swift-only `ASCredentialDataManager` in
 * `platform.AuthenticationServices`, so the iOS host app owns that call and adapts it here.
 */
interface IosCredentialSignalBridge {
    val isAvailable: Boolean

    fun reportCurrentUserDetails(
        relyingPartyIdentifier: String,
        userHandleBase64Url: String,
        name: String,
        displayName: String,
        completion: (String?) -> Unit,
    )
}

internal class IosBridgeCredentialSignalDemoClient(
    private val bridge: IosCredentialSignalBridge,
) : CredentialSignalDemoClient {
    override val isAvailable: Boolean
        get() = bridge.isAvailable

    override suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
    ): PasskeyResult<Unit> {
        if (!bridge.isAvailable) {
            return PasskeyResult.Failure(
                PasskeyClientError.Platform("iOS credential signals require iOS 26.2+ ASCredentialDataManager."),
            )
        }
        return suspendCancellableCoroutine { continuation ->
            bridge.reportCurrentUserDetails(
                relyingPartyIdentifier = rpId.value,
                userHandleBase64Url = userId.value.encoded(),
                name = name,
                displayName = displayName,
            ) { errorMessage ->
                if (!continuation.isActive) return@reportCurrentUserDetails
                continuation.resume(
                    if (errorMessage == null) {
                        PasskeyResult.Success(Unit)
                    } else {
                        PasskeyResult.Failure(PasskeyClientError.Platform(errorMessage))
                    },
                )
            }
        }
    }
}
