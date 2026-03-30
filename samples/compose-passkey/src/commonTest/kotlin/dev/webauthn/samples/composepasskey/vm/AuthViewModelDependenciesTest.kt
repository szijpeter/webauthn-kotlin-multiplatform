package dev.webauthn.samples.composepasskey.vm

import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
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
import dev.webauthn.model.WebAuthnValidationError
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.resetMain
import kotlin.test.Test
import kotlin.test.assertEquals

@OptIn(ExperimentalCoroutinesApi::class)
class AuthViewModelDependenciesTest {
    @Test
    fun register_uses_injected_dependencies() = runMainBoundTest {
        val server = CountingServerClient(
            registerOptions = ValidationResult.Valid(validCreationOptions()),
        )
        val passkeyClient = StubPasskeyClient()
        val viewModel = createViewModel(
            passkeyClient = passkeyClient,
            serverClient = server,
        )
        viewModel.onRegisterClicked()
        advanceUntilIdle()

        assertEquals(1, server.registerOptionsCalls)
        assertEquals(1, passkeyClient.createCredentialCalls)

        viewModel.viewModelScope.cancel()
    }

    private fun runMainBoundTest(block: suspend TestScope.() -> Unit) = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        try {
            block()
        } finally {
            Dispatchers.resetMain()
        }
    }

    private fun createViewModel(
        passkeyClient: PasskeyClient = StubPasskeyClient(),
        serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> = CountingServerClient(),
    ): AuthViewModel {
        return AuthViewModel(
            config = PasskeyDemoConfig(
                endpointBase = "https://example.test",
                rpId = "example.test",
                origin = "https://example.test",
                userHandle = "demo-user-1",
                userName = "demo@local",
            ),
            debugLogs = DebugLogStore(),
            sessionStore = AppSessionStore(),
            passkeyClient = passkeyClient,
            serverClient = serverClient,
        )
    }
}

private class CountingServerClient(
    private val registerOptions: ValidationResult<PublicKeyCredentialCreationOptions> = ValidationResult.Invalid(
        errors = listOf(
            WebAuthnValidationError.InvalidValue(
                field = "register",
                message = "invalid for test",
            ),
        ),
    ),
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    var registerOptionsCalls: Int = 0
        private set

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        registerOptionsCalls += 1
        return registerOptions
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
                    message = "invalid for test",
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

private class StubPasskeyClient : PasskeyClient {
    var createCredentialCalls: Int = 0
        private set

    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        createCredentialCalls += 1
        return PasskeyResult.Failure(PasskeyClientError.Platform("not used in test"))
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return PasskeyResult.Failure(PasskeyClientError.Platform("not used in test"))
    }
}

private fun validCreationOptions(): PublicKeyCredentialCreationOptions {
    return PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(id = RpId.parseOrThrow("example.test"), name = "Example"),
        user = PublicKeyCredentialUserEntity(
            id = UserHandle.fromBytes(byteArrayOf(1, 2, 3)),
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
}
