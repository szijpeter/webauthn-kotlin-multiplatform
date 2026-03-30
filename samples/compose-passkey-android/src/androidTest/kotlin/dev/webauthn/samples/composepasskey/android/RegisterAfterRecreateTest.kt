package dev.webauthn.samples.composepasskey.android

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.ComposePasskeySampleOverrides
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.rules.TestRule
import org.junit.rules.TestWatcher
import org.junit.runner.Description
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

@RunWith(AndroidJUnit4::class)
class RegisterAfterRecreateTest {
    private lateinit var fakeServerClient: CountingServerClient

    private val composeRule = createAndroidComposeRule<MainActivity>()

    private val overridesRule = object : TestWatcher() {
        override fun starting(description: Description) {
            fakeServerClient = CountingServerClient()
            ComposePasskeySampleOverrides.passkeyClientOverride = NoopPasskeyClient()
            ComposePasskeySampleOverrides.serverClientOverride = fakeServerClient
        }

        override fun finished(description: Description) {
            ComposePasskeySampleOverrides.reset()
        }
    }

    @get:Rule
    val rules: TestRule = RuleChain.outerRule(overridesRule).around(composeRule)

    @Test
    fun register_action_invokes_server_before_and_after_recreate() {
        composeRule.onNodeWithText("Register").assertIsEnabled().performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            fakeServerClient.registerOptionsCalls.get() == 1
        }

        composeRule.activityRule.scenario.recreate()
        composeRule.waitForIdle()

        composeRule.onNodeWithText("Register").assertIsEnabled().performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            fakeServerClient.registerOptionsCalls.get() == 2
        }
    }
}

private class NoopPasskeyClient : PasskeyClient {
    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        return PasskeyResult.Failure(PasskeyClientError.Platform("createCredential not expected in test"))
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return PasskeyResult.Failure(PasskeyClientError.Platform("getAssertion not expected in test"))
    }

    override suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
}

private class CountingServerClient :
    PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    val registerOptionsCalls: AtomicInteger = AtomicInteger(0)

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        registerOptionsCalls.incrementAndGet()
        return ValidationResult.Invalid(
            errors = listOf(
                WebAuthnValidationError.InvalidValue(
                    field = "register",
                    message = "Fake invalid register options for lifecycle test",
                ),
            ),
        )
    }

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = PasskeyFinishResult.Verified

    override suspend fun getSignInOptions(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        return ValidationResult.Invalid(
            errors = listOf(
                WebAuthnValidationError.InvalidValue(
                    field = "signIn",
                    message = "Fake invalid sign-in options for lifecycle test",
                ),
            ),
        )
    }

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = PasskeyFinishResult.Verified
}
