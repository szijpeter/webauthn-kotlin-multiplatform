package dev.webauthn.samples.composepasskey.domain.restore

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.android.AndroidRestoreCredentialClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

@Composable
internal actual fun rememberRestoreCredentialDemoClient(): RestoreCredentialDemoClient {
    val context = LocalContext.current
    return remember(context) {
        AndroidRestoreCredentialDemoClient(AndroidRestoreCredentialClient(context))
    }
}

private class AndroidRestoreCredentialDemoClient(
    private val delegate: AndroidRestoreCredentialClient,
) : RestoreCredentialDemoClient {
    override val isAvailable: Boolean = true

    override suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean,
    ): PasskeyResult<RegistrationResponse> {
        return delegate.createRestoreCredential(
            options = options,
            isCloudBackupEnabled = isCloudBackupEnabled,
        )
    }

    override suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return delegate.getRestoreCredential(options)
    }

    override suspend fun clearRestoreCredential(): PasskeyResult<Unit> {
        return delegate.clearRestoreCredential()
    }
}
