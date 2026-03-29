package dev.webauthn.samples.composepasskey

import androidx.activity.ComponentActivity
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import java.lang.ref.WeakReference

private object ActivityHolder {
    @Volatile
    private var activityRef: WeakReference<ComponentActivity> = WeakReference(null)

    fun update(activity: ComponentActivity) {
        activityRef = WeakReference(activity)
    }

    fun requireCurrentActivity(): ComponentActivity {
        return checkNotNull(activityRef.get()) {
            "No active ComponentActivity is registered for the compose-passkey sample."
        }
    }
}

private object ActivityAwarePasskeyClient : PasskeyClient {
    private fun activeClient(): AndroidPasskeyClient = AndroidPasskeyClient(ActivityHolder.requireCurrentActivity())

    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        return activeClient().createCredential(options)
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return activeClient().getAssertion(options)
    }

    override suspend fun capabilities() = activeClient().capabilities()
}

fun initializeComposePasskeySampleAppKoin(activity: ComponentActivity) {
    ActivityHolder.update(activity)
    initializeSampleAppKoin(passkeyClient = ActivityAwarePasskeyClient)
}
