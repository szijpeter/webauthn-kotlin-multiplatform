package dev.webauthn.client.android

import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.os.CancellationSignal
import androidx.activity.ComponentActivity
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PrepareGetCredentialResponse
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.webauthn.client.PasskeyClient
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import java.util.concurrent.Executor
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RotationSafePasskeyPromptContextTest {
    @Test
    fun registration_after_recreate_uses_the_new_activity_context() {
        val scenario = ActivityScenario.launch(RuntimeHostActivity::class.java)
        try {
            var firstActivityId = -1
            var retainedViewModelId = -1

            scenario.onActivity { activity ->
                firstActivityId = System.identityHashCode(activity)
                retainedViewModelId = System.identityHashCode(activity.viewModel)

                runBlocking { activity.viewModel.createCredential() }

                assertEquals(listOf(firstActivityId), activity.viewModel.createContextIdentityIds)
            }

            scenario.recreate()

            scenario.onActivity { activity ->
                val recreatedActivityId = System.identityHashCode(activity)
                assertNotEquals(firstActivityId, recreatedActivityId)
                assertEquals(retainedViewModelId, System.identityHashCode(activity.viewModel))

                runBlocking { activity.viewModel.createCredential() }

                assertEquals(
                    listOf(firstActivityId, recreatedActivityId),
                    activity.viewModel.createContextIdentityIds,
                )
            }
        } finally {
            scenario.close()
        }
    }

    @Test
    fun authentication_after_recreate_uses_the_new_activity_context() {
        val scenario = ActivityScenario.launch(RuntimeHostActivity::class.java)
        try {
            var firstActivityId = -1
            var retainedViewModelId = -1

            scenario.onActivity { activity ->
                firstActivityId = System.identityHashCode(activity)
                retainedViewModelId = System.identityHashCode(activity.viewModel)

                runBlocking { activity.viewModel.getAssertion() }

                assertEquals(listOf(firstActivityId), activity.viewModel.getContextIdentityIds)
            }

            scenario.recreate()

            scenario.onActivity { activity ->
                val recreatedActivityId = System.identityHashCode(activity)
                assertNotEquals(firstActivityId, recreatedActivityId)
                assertEquals(retainedViewModelId, System.identityHashCode(activity.viewModel))

                runBlocking { activity.viewModel.getAssertion() }

                assertEquals(
                    listOf(firstActivityId, recreatedActivityId),
                    activity.viewModel.getContextIdentityIds,
                )
            }
        } finally {
            scenario.close()
        }
    }
}

class RuntimeHostActivity : ComponentActivity() {
    val viewModel: RuntimeHostViewModel by lazy(LazyThreadSafetyMode.NONE) {
        ViewModelProvider(
            this,
            RuntimeHostViewModel.factory(
                application = application,
                contextHint = this,
            ),
        )[RuntimeHostViewModel::class.java]
    }
}

class RuntimeHostViewModel(
    application: Application,
    contextHint: Context,
) : ViewModel() {
    private val credentialManager = RecordingCredentialManager()
    private val passkeyClient: PasskeyClient = AndroidPasskeyClient(
        contextProvider = ForegroundActivityPasskeyPromptContextProvider.forApplication(
            application = application,
            contextHint = contextHint,
        ),
        credentialManagerFactory = { credentialManager },
        codec = KotlinxWebAuthnJsonCodec(),
    )

    val createContextIdentityIds: List<Int>
        get() = credentialManager.createContextIdentityIds.toList()

    val getContextIdentityIds: List<Int>
        get() = credentialManager.getContextIdentityIds.toList()

    suspend fun createCredential() {
        val _ = passkeyClient.createCredential(registrationOptions())
    }

    suspend fun getAssertion() {
        val _ = passkeyClient.getAssertion(authenticationOptions())
    }

    companion object {
        fun factory(
            application: Application,
            contextHint: Context,
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass.isAssignableFrom(RuntimeHostViewModel::class.java)) {
                    "Unsupported ViewModel class: ${modelClass.name}"
                }
                return RuntimeHostViewModel(application, contextHint) as T
            }
        }
    }
}

private class RecordingCredentialManager : CredentialManager {
    val createContextIdentityIds: MutableList<Int> = mutableListOf()
    val getContextIdentityIds: MutableList<Int> = mutableListOf()

    override fun createCredentialAsync(
        context: Context,
        request: CreateCredentialRequest,
        cancellationSignal: CancellationSignal?,
        executor: Executor,
        callback: CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException>,
    ) {
        createContextIdentityIds += System.identityHashCode(context)
        executor.execute { callback.onError(CreateCredentialCancellationException("Cancelled")) }
    }

    override fun getCredentialAsync(
        context: Context,
        request: GetCredentialRequest,
        cancellationSignal: CancellationSignal?,
        executor: Executor,
        callback: CredentialManagerCallback<GetCredentialResponse, GetCredentialException>,
    ) {
        getContextIdentityIds += System.identityHashCode(context)
        executor.execute { callback.onError(GetCredentialCancellationException("Cancelled")) }
    }

    override fun getCredentialAsync(
        context: Context,
        pendingGetCredentialHandle: PrepareGetCredentialResponse.PendingGetCredentialHandle,
        cancellationSignal: CancellationSignal?,
        executor: Executor,
        callback: CredentialManagerCallback<GetCredentialResponse, GetCredentialException>,
    ) {
        throw UnsupportedOperationException("Pending getCredential is not used in this test")
    }

    override fun prepareGetCredentialAsync(
        request: GetCredentialRequest,
        cancellationSignal: CancellationSignal?,
        executor: Executor,
        callback: CredentialManagerCallback<PrepareGetCredentialResponse, GetCredentialException>,
    ) {
        throw UnsupportedOperationException("prepareGetCredential is not used in this test")
    }

    override fun clearCredentialStateAsync(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal?,
        executor: Executor,
        callback: CredentialManagerCallback<Void?, ClearCredentialException>,
    ) {
        executor.execute { callback.onResult(null) }
    }

    override fun createSettingsPendingIntent(): PendingIntent {
        throw UnsupportedOperationException("Settings pending intent is not used in this test")
    }
}

private fun registrationOptions() = PublicKeyCredentialCreationOptions(
    rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.test"), "Example"),
    user = PublicKeyCredentialUserEntity(
        id = UserHandle.fromBytes(byteArrayOf(1)),
        name = "demo",
        displayName = "Demo User",
    ),
    challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
    pubKeyCredParams = listOf(
        PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = -7,
        ),
    ),
)

private fun authenticationOptions() = PublicKeyCredentialRequestOptions(
    challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
    rpId = RpId.parseOrThrow("example.test"),
)
