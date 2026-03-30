package dev.webauthn.samples.composepasskey.vm

import androidx.lifecycle.viewModelScope
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
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
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.model.WebAuthnValidationError
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.InMemoryPrfSaltStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class AuthViewModelRuntimeBindingTest {
    @Test
    fun register_uses_latest_bound_server_client() = runMainBoundTest {
        val viewModel = createViewModel()
        val firstServer = CountingServerClient()
        val secondServer = CountingServerClient()
        val passkeyClient = StubPasskeyClient(capabilities = PasskeyCapabilities())

        viewModel.bindRuntimeDependencies(passkeyClient = passkeyClient, serverClient = firstServer)
        viewModel.onRegisterClicked()
        advanceUntilIdle()

        viewModel.bindRuntimeDependencies(passkeyClient = passkeyClient, serverClient = secondServer)
        viewModel.onRegisterClicked()
        advanceUntilIdle()

        assertEquals(1, firstServer.registerOptionsCalls)
        assertEquals(1, secondServer.registerOptionsCalls)

        viewModel.viewModelScope.cancel()
    }

    @Test
    fun bind_runtime_dependencies_refreshes_capabilities_from_latest_client() = runMainBoundTest {
        val viewModel = createViewModel()
        val serverClient = CountingServerClient()
        val withoutPrf = StubPasskeyClient(capabilities = PasskeyCapabilities())
        val withPrf = StubPasskeyClient(
            capabilities = PasskeyCapabilities(
                supported = setOf(PasskeyCapability.Extension(WebAuthnExtension.Prf)),
            ),
        )

        viewModel.bindRuntimeDependencies(passkeyClient = withoutPrf, serverClient = serverClient)
        advanceUntilIdle()
        assertFalse(viewModel.uiState.value.capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.Prf)))

        viewModel.bindRuntimeDependencies(passkeyClient = withPrf, serverClient = serverClient)
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value.capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.Prf)))

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

    private fun createViewModel(): AuthViewModel {
        return AuthViewModel(
            config = PasskeyDemoConfig(
                endpointBase = "https://example.test",
                rpId = "example.test",
                origin = "https://example.test",
                userHandle = "demo-user-1",
                userName = "demo@local",
            ),
            debugLogs = DebugLogStore(),
            saltStore = InMemoryPrfSaltStore(),
        )
    }
}

private class CountingServerClient : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    var registerOptionsCalls: Int = 0
        private set

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        registerOptionsCalls += 1
        return ValidationResult.Invalid(
            errors = listOf(
                WebAuthnValidationError.InvalidValue(
                    field = "register",
                    message = "invalid for test",
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

private class StubPasskeyClient(
    private val capabilities: PasskeyCapabilities,
) : PasskeyClient {
    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        return PasskeyResult.Failure(PasskeyClientError.Platform("not used in test"))
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return PasskeyResult.Failure(PasskeyClientError.Platform("not used in test"))
    }

    override suspend fun capabilities(): PasskeyCapabilities = capabilities
}
