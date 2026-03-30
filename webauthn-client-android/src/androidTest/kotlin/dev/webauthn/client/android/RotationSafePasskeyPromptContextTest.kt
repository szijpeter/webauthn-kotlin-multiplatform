package dev.webauthn.client.android

import androidx.activity.ComponentActivity
import androidx.lifecycle.ViewModel
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyResult
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
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RotationSafePasskeyPromptContextTest {
    @Test
    fun register_after_recreate_uses_updated_prompt_context() {
        val scenario = ActivityScenario.launch(RuntimeHostActivity::class.java)
        try {
            var firstContextId = -1
            scenario.onActivity { activity ->
                runBlocking { activity.viewModel.register() }
                firstContextId = activity.viewModel.usedContextIdentityIds.single()
            }

            scenario.recreate()

            scenario.onActivity { activity ->
                runBlocking { activity.viewModel.register() }
                val contextIds = activity.viewModel.usedContextIdentityIds
                assertEquals(2, contextIds.size)
                assertNotEquals(firstContextId, contextIds.last())
                assertTrue(activity.viewModel.registerStartCalls >= 2)
            }
        } finally {
            scenario.close()
        }
    }
}

class RuntimeHostActivity : ComponentActivity() {
    val viewModel: RuntimeHostViewModel by lazy {
        androidx.lifecycle.ViewModelProvider(this)[RuntimeHostViewModel::class.java]
    }

    override fun onResume() {
        super.onResume()
        viewModel.updateContext(this)
    }
}

class RuntimeHostViewModel : ViewModel() {
    private val contextProvider = MutablePasskeyPromptContextProvider()
    private val fakeServerClient = RuntimeTestServerClient()
    private val fakePasskeyClient = RuntimeAwareFakePasskeyClient(contextProvider)
    private val controller = PasskeyController(
        passkeyClient = fakePasskeyClient,
        serverClient = fakeServerClient,
    )

    val usedContextIdentityIds: List<Int>
        get() = fakePasskeyClient.usedContextIdentityIds.toList()

    val registerStartCalls: Int
        get() = fakeServerClient.registerStartCalls

    fun updateContext(activity: ComponentActivity) {
        contextProvider.update(activity)
    }

    suspend fun register() {
        controller.register(
            "demo-user",
        )
    }
}

private class RuntimeAwareFakePasskeyClient(
    private val contextProvider: MutablePasskeyPromptContextProvider,
) : PasskeyClient {
    val usedContextIdentityIds: MutableList<Int> = mutableListOf()

    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        val context = contextProvider.currentContextOrNull()
            ?: return PasskeyResult.Failure(PasskeyClientError.Platform("No active UI context"))
        usedContextIdentityIds += System.identityHashCode(context)
        return PasskeyResult.Failure(PasskeyClientError.UserCancelled())
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return PasskeyResult.Failure(PasskeyClientError.UserCancelled())
    }
}

private class RuntimeTestServerClient :
    PasskeyServerClient<String, String> {
    var registerStartCalls: Int = 0
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
