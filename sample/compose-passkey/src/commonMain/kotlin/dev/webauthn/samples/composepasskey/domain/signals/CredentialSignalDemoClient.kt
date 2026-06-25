package dev.webauthn.samples.composepasskey.domain.signals

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle

internal interface CredentialSignalDemoClient {
    val isAvailable: Boolean

    suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
    ): PasskeyResult<Unit>
}

internal class UnsupportedCredentialSignalDemoClient : CredentialSignalDemoClient {
    override val isAvailable: Boolean = false

    override suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
    ): PasskeyResult<Unit> {
        return PasskeyResult.Failure(
            PasskeyClientError.Platform(
                "Credential signals are not wired for this platform in the KMP sample.",
            ),
        )
    }
}
