package dev.webauthn.samples.composepasskey.domain.signals

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.android.AndroidCredentialSignalClient
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle

@Composable
internal actual fun rememberCredentialSignalDemoClient(): CredentialSignalDemoClient {
    val context = LocalContext.current
    return remember(context) {
        AndroidCredentialSignalDemoClient(AndroidCredentialSignalClient(context))
    }
}

private class AndroidCredentialSignalDemoClient(
    private val delegate: AndroidCredentialSignalClient,
) : CredentialSignalDemoClient {
    override val isAvailable: Boolean = true

    override suspend fun signalCurrentUserDetails(
        rpId: RpId,
        userId: UserHandle,
        name: String,
        displayName: String,
    ): PasskeyResult<Unit> {
        return delegate.signalCurrentUserDetails(
            rpId = rpId,
            userId = userId,
            name = name,
            displayName = displayName,
        )
    }
}
