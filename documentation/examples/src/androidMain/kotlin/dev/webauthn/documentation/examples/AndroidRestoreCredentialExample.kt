package dev.webauthn.documentation.examples

// docs-region android-restore-client
import android.app.Activity
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.android.AndroidRestoreCredentialClient
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

suspend fun exerciseRestoreCredentials(
    activity: Activity,
    creationOptions: PublicKeyCredentialCreationOptions,
    requestOptions: PublicKeyCredentialRequestOptions,
): Triple<
    PasskeyResult<RawRegistrationResponse>,
    PasskeyResult<RawAuthenticationResponse>,
    PasskeyResult<Unit>,
> {
    val restoreCredentials = AndroidRestoreCredentialClient(
        context = activity.applicationContext,
        codec = KotlinxWebAuthnJsonCodec(),
    )

    return Triple(
        restoreCredentials.createRestoreCredential(creationOptions),
        restoreCredentials.getRestoreCredential(requestOptions),
        restoreCredentials.clearRestoreCredential(),
    )
}
// docs-endregion android-restore-client
