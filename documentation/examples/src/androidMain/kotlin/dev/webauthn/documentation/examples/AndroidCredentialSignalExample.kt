package dev.webauthn.documentation.examples

// docs-region android-credential-signals
import android.app.Activity
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.android.AndroidCredentialSignalClient
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle

suspend fun reconcileCredentialManager(
    activity: Activity,
    rpId: RpId,
    userHandle: UserHandle,
    acceptedCredentialIds: List<CredentialId>,
    unknownCredentialId: CredentialId,
): Triple<PasskeyResult<Unit>, PasskeyResult<Unit>, PasskeyResult<Unit>> {
    val signals = AndroidCredentialSignalClient(activity.applicationContext)
    return Triple(
        signals.signalAllAcceptedCredentialIds(rpId, userHandle, acceptedCredentialIds),
        signals.signalUnknownCredential(rpId, unknownCredentialId),
        signals.signalCurrentUserDetails(
            rpId = rpId,
            userId = userHandle,
            name = "demo@example.com",
            displayName = "Demo User",
        ),
    )
}
// docs-endregion android-credential-signals
