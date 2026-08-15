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
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import java.util.concurrent.Executor
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RotationSafePasskeyPromptContextTest {
    @Test
    fun register_after_recreate_uses_updated_prompt_context_via_android_bridge() {
        val scenario = ActivityScenario.launch(RuntimeHostActivity::class.java)
        try {
            var firstActivityId = -1
            var retainedViewModelId = -1

            scenario.onActivity { activity ->
                firstActivityId = System.identityHashCode(activity)
                retainedViewModelId = System.identityHashCode(activity.viewModel)

                runBlocking { activity.viewModel.register() }

                assertEquals(
                    listOf(firstActivityId),
                    activity.viewModel.registerPromptContextIdentityIds,
                )
                assertEquals(1, activity.viewModel.registerStartCalls)
            }

            scenario.recreate()

            scenario.onActivity { activity ->
                val recreatedActivityId = System.identityHashCode(activity)
                assertNotEquals(firstActivityId, recreatedActivityId)
                assertEquals(retainedViewModelId, System.identityHashCode(activity.viewModel))

                runBlocking { activity.viewModel.register() }

                val contextIds = activity.viewModel.registerPromptContextIdentityIds
                assertEquals(2, contextIds.size)
                assertEquals(recreatedActivityId, contextIds.last())
                assertNotEquals(firstActivityId, contextIds.last())
                assertEquals(2, activity.viewModel.registerStartCalls)
            }
        } finally {
            scenario.close()
        }
    }

    @Test
    fun sign_in_after_recreate_uses_updated_prompt_context_via_android_bridge() {
        val scenario = ActivityScenario.launch(RuntimeHostActivity::class.java)
        try {
            var firstActivityId = -1
            var retainedViewModelId = -1

            scenario.onActivity { activity ->
                firstActivityId = System.identityHashCode(activity)
                retainedViewModelId = System.identityHashCode(activity.viewModel)

                runBlocking { activity.viewModel.signIn() }

                assertEquals(
                    listOf(firstActivityId),
                    activity.viewModel.signInPromptContextIdentityIds,
                )
                assertEquals(1, activity.viewModel.signInStartCalls)
            }

            scenario.recreate()

            scenario.onActivity { activity ->
                val recreatedActivityId = System.identityHashCode(activity)
                assertNotEquals(firstActivityId, recreatedActivityId)
                assertEquals(retainedViewModelId, System.identityHashCode(activity.viewModel))

                runBlocking { activity.viewModel.signIn() }

                val contextIds = activity.viewModel.signInPromptContextIdentityIds
                assertEquals(2, contextIds.size)
                assertEquals(recreatedActivityId, contextIds.last())
                assertNotEquals(firstActivityId, contextIds.last())
                assertEquals(2, activity.viewModel.signInStartCalls)
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
    private val fakeServerClient = RuntimeTestServerClient()
    private val controller = PasskeyController(
        passkeyClient = AndroidPasskeyClient(
            contextProvider = ForegroundActivityPasskeyPromptContextProvider.forApplication(
                application = application,
                contextHint = contextHint,
            ),
            credentialManagerFactory = { credentialManager },
        ),
        serverClient = fakeServerClient,
    )

    val registerPromptContextIdentityIds: List<Int>
        get() = credentialManager.createContextIdentityIds.toList()

    val signInPromptContextIdentityIds: List<Int>
        get() = credentialManager.getContextIdentityIds.toList()

    val registerStartCalls: Int
        get() = fakeServerClient.registerStartCalls

    val signInStartCalls: Int
        get() = fakeServerClient.signInStartCalls

    suspend fun register() {
        controller.register("demo-user")
    }

    suspend fun signIn() {
        controller.signIn("demo-user")
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
                return RuntimeHostViewModel(
                    application = application,
                    contextHint = contextHint,
                ) as T
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
        executor.execute {
            callback.onError(CreateCredentialCancellationException("Cancelled"))
        }
    }

    override fun getCredentialAsync(
        context: Context,
        request: GetCredentialRequest,
        cancellationSignal: CancellationSignal?,
        executor: Executor,
        callback: CredentialManagerCallback<GetCredentialResponse, GetCredentialException>,
    ) {
        getContextIdentityIds += System.identityHashCode(context)
        executor.execute {
            callback.onError(GetCredentialCancellationException("Cancelled"))
        }
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
        executor.execute {
            callback.onResult(null)
        }
    }

    override fun createSettingsPendingIntent(): PendingIntent {
        throw UnsupportedOperationException("Settings pending intent is not used in this test")
    }
}

private class RuntimeTestServerClient : PasskeyServerClient<String, String> {
    var registerStartCalls: Int = 0
        private set

    var signInStartCalls: Int = 0
        private set

    override suspend fun getRegisterOptions(
        params: String,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        registerStartCalls += 1
        return ValidationResult.Valid(
            PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(
                    id = RpId.parseOrThrow("example.test"),
                    name = "Example",
                ),
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
            ),
        )
    }

    override suspend fun finishRegister(
        params: String,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = PasskeyFinishResult.Verified

    override suspend fun getSignInOptions(
        params: String,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        signInStartCalls += 1
        return ValidationResult.Valid(
            PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.test"),
            ),
        )
    }

    override suspend fun finishSignIn(
        params: String,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = PasskeyFinishResult.Verified
}
