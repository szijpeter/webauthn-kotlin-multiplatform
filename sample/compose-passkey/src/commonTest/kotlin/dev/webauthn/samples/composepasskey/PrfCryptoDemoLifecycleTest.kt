@file:OptIn(dev.webauthn.model.ExperimentalWebAuthnL3Api::class)

package dev.webauthn.samples.composepasskey

import androidx.lifecycle.ViewModelStore
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.ui.screens.main.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.resetMain
import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.network.kotlinx.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.domain.prf.PrfDemoResult
import dev.webauthn.samples.composepasskey.domain.prf.PrfSaltStore
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PrfCryptoDemoLifecycleTest {
    @Test
    fun clearing_during_finish_prevents_late_session_activation() = runTest {
        val finishEntered = CompletableDeferred<Unit>()
        val releaseFinish = CompletableDeferred<Unit>()
        val controller = controller(
            FakePrfBackend(finishAction = { _, _ ->
                finishEntered.complete(Unit)
                releaseFinish.await()
                DefaultPasskeyFinishResult.Verified
            }),
        )
        val signIn = async { controller.signInWithPrf(config(), supportsPrf = true) }
        finishEntered.await()

        controller.clearSession()
        releaseFinish.complete(Unit)
        signIn.await()

        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
        assertIs<PrfDemoResult.Failure>(controller.encrypt("should remain locked"))
    }

    @Test
    fun clearing_during_start_does_not_open_a_platform_prompt() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val client = FakePrfPasskeyClient()
        val controller = controller(FakePrfBackend(startAction = {
            entered.complete(Unit)
            release.await()
            CeremonyStart(Unit, defaultPrfOptions())
        }), passkeyClient = client)
        val operation = async { controller.signInWithPrf(config(), supportsPrf = true) }
        entered.await()
        controller.clearSession()
        release.complete(Unit)

        assertIs<PrfDemoResult.Failure>(operation.await())
        assertEquals(0, client.assertionCalls)
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun clearing_during_platform_prompt_skips_backend_finish() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val backend = FakePrfBackend()
        val client = FakePrfPasskeyClient(beforeAssertion = {
            entered.complete(Unit)
            release.await()
        })
        val controller = controller(backend, passkeyClient = client)
        val operation = async { controller.signInWithPrf(config(), supportsPrf = true) }
        entered.await()
        controller.clearSession()
        release.complete(Unit)

        assertIs<PrfDemoResult.Failure>(operation.await())
        assertEquals(0, backend.finishCalls)
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun temporary_host_inactivity_during_prompt_allows_verified_session_after_return() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var foreground = true
        val backend = FakePrfBackend()
        val client = FakePrfPasskeyClient(beforeAssertion = {
            entered.complete(Unit)
            release.await()
        })
        val controller = controller(backend, passkeyClient = client, isForeground = { foreground })
        val operation = async { controller.signInWithPrf(config(), supportsPrf = true) }
        entered.await()
        assertTrue(controller.isPlatformPromptInProgress)
        foreground = false
        controller.lockCurrentSession()
        foreground = true
        release.complete(Unit)

        assertIs<PrfDemoResult.Success>(operation.await())
        assertEquals(1, backend.finishCalls)
        assertEquals(PrfCryptoDemoSessionState.SessionReady, controller.sessionState)
    }

    @Test
    fun backgrounded_host_does_not_verify_or_activate_a_returned_platform_session() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var foreground = true
        val backend = FakePrfBackend()
        val client = FakePrfPasskeyClient(beforeAssertion = {
            entered.complete(Unit)
            release.await()
        })
        val controller = controller(backend, passkeyClient = client, isForeground = { foreground })
        val operation = async { controller.signInWithPrf(config(), supportsPrf = true) }
        entered.await()
        foreground = false
        controller.lockCurrentSession()
        release.complete(Unit)

        assertIs<PrfDemoResult.Failure>(operation.await())
        assertEquals(0, backend.finishCalls)
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun unsupported_capability_does_not_start_backend() = runTest {
        val backend = FakePrfBackend()
        val controller = controller(backend)

        val result = controller.signInWithPrf(config(), supportsPrf = false)

        assertIs<PrfDemoResult.Failure>(result)
        assertTrue(result.message.contains("does not report PRF support"))
        assertEquals(0, backend.startCalls)
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun successful_sign_in_encrypts_and_decrypts_then_clears_session() = runTest {
        val controller = controller(FakePrfBackend())

        assertIs<PrfDemoResult.Success>(controller.signInWithPrf(config(), supportsPrf = true))
        assertEquals(PrfCryptoDemoSessionState.SessionReady, controller.sessionState)
        assertIs<PrfDemoResult.Success>(controller.encrypt("hello prf"))
        assertEquals(PrfCryptoDemoSessionState.CiphertextReady, controller.sessionState)
        val decrypted = assertIs<PrfDemoResult.Success>(controller.decrypt())
        assertEquals("hello prf", decrypted.plaintext)

        assertIs<PrfDemoResult.Success>(controller.clearSession())
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun success_message_omits_user_scope_and_key_material() = runTest {
        val result = assertIs<PrfDemoResult.Success>(controller(FakePrfBackend()).signInWithPrf(config(), true))
        assertEquals("PRF session ready. Caller-owned salt is available.", result.message)
        assertTrue(!result.message.contains(config().userHandle))
    }

    @Test
    fun decrypt_requires_ciphertext_after_sign_in() = runTest {
        val controller = controller(FakePrfBackend())
        assertIs<PrfDemoResult.Success>(controller.signInWithPrf(config(), supportsPrf = true))

        val failure = assertIs<PrfDemoResult.Failure>(controller.decrypt())
        assertTrue(failure.message.contains("Encrypt text first"))
    }

    @Test
    fun backend_rejection_from_finish_does_not_transfer_temporary_session() = runTest {
        val backend = FakePrfBackend(
            finishAction = { _, _ -> DefaultPasskeyFinishResult.Rejected("no") },
        )
        val controller = controller(backend)

        val result = controller.signInWithPrf(config(), supportsPrf = true)

        assertIs<PrfDemoResult.Failure>(result)
        assertTrue(result.message.contains("rejected"))
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun backend_start_exception_is_reported_without_creating_session() = runTest {
        val controller = controller(
            FakePrfBackend(startAction = { error("start failed") }),
        )

        val result = controller.signInWithPrf(config(), supportsPrf = true)

        assertIs<PrfDemoResult.Failure>(result)
        assertTrue(result.message.contains("Could not start"))
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun backend_finish_exception_is_reported_without_creating_session() = runTest {
        val controller = controller(
            FakePrfBackend(finishAction = { _, _ -> error("finish failed") }),
        )

        val result = controller.signInWithPrf(config(), supportsPrf = true)

        assertIs<PrfDemoResult.Failure>(result)
        assertTrue(result.message.contains("Could not verify"))
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun backend_start_cancellation_propagates() = runTest {
        val controller = controller(
            FakePrfBackend(startAction = { throw CancellationException("start cancelled") }),
        )

        assertFailsWith<CancellationException> {
            controller.signInWithPrf(config(), supportsPrf = true)
        }
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun backend_finish_cancellation_propagates_and_clears_temporary_session() = runTest {
        val controller = controller(
            FakePrfBackend(finishAction = { _, _ -> throw CancellationException("finish cancelled") }),
        )

        assertFailsWith<CancellationException> {
            controller.signInWithPrf(config(), supportsPrf = true)
        }
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun salt_scope_ignores_user_name_changes() = runTest {
        val saltStore = FixedSaltStore()
        val controller = controller(
            backend = FakePrfBackend(),
            saltStore = saltStore,
            passkeyClient = FakePrfPasskeyClient(mutableListOf(successfulAssertion(), successfulAssertion())),
        )

        assertIs<PrfDemoResult.Success>(controller.signInWithPrf(config(), supportsPrf = true))
        assertIs<PrfDemoResult.Success>(
            controller.signInWithPrf(config().copy(userName = "another@local"), supportsPrf = true),
        )

        assertEquals(listOf("example.test:demo-user-1", "example.test:demo-user-1"), saltStore.requestedKeys)
    }

    @Test
    fun clearing_an_empty_session_is_harmless() = runTest {
        val controller = controller(FakePrfBackend())

        assertIs<PrfDemoResult.Success>(controller.clearSession())
        assertIs<PrfDemoResult.Success>(controller.clearSession())
        assertEquals(PrfCryptoDemoSessionState.NoSession, controller.sessionState)
    }

    @Test
    fun second_successful_sign_in_replaces_session_and_discards_old_ciphertext() = runTest {
        val client = FakePrfPasskeyClient(mutableListOf(successfulAssertion(), successfulAssertion()))
        val controller = controller(FakePrfBackend(), passkeyClient = client)

        assertIs<PrfDemoResult.Success>(controller.signInWithPrf(config(), supportsPrf = true))
        assertIs<PrfDemoResult.Success>(controller.encrypt("old ciphertext"))
        assertIs<PrfDemoResult.Success>(controller.signInWithPrf(config(), supportsPrf = true))

        val result = assertIs<PrfDemoResult.Failure>(controller.decrypt())
        assertTrue(result.message.contains("Encrypt text first"))
        assertEquals(PrfCryptoDemoSessionState.SessionReady, controller.sessionState)
    }

    @Test
    fun failed_second_sign_in_keeps_existing_session_and_does_not_transfer_new_session() = runTest {
        val client = FakePrfPasskeyClient(mutableListOf(successfulAssertion(), successfulAssertion()))
        var finishes = 0
        val backend = FakePrfBackend(
            finishAction = { _, _ ->
                finishes += 1
                if (finishes == 1) DefaultPasskeyFinishResult.Verified
                else DefaultPasskeyFinishResult.Rejected("second sign-in rejected")
            },
        )
        val controller = controller(backend, passkeyClient = client)

        assertIs<PrfDemoResult.Success>(controller.signInWithPrf(config(), supportsPrf = true))
        assertIs<PrfDemoResult.Success>(controller.encrypt("keep this"))
        val result = assertIs<PrfDemoResult.Failure>(controller.signInWithPrf(config(), supportsPrf = true))

        assertTrue(result.message.contains("rejected"))
        assertEquals(PrfCryptoDemoSessionState.CiphertextReady, controller.sessionState)
        val decrypted = assertIs<PrfDemoResult.Success>(controller.decrypt())
        assertEquals("keep this", decrypted.plaintext)
    }
}

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class MainViewModelLifecycleTest {
    @Test
    fun disposing_owner_clears_active_session_and_plaintext() = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        val owner = ViewModelStore()
        try {
            val viewModel = mainViewModel()
            owner.put("demo", viewModel)
            viewModel.uiState.first { it.supportsPrf }
            viewModel.onSignInWithPrfClicked()
            viewModel.uiState.first { !it.busy && it.sessionState == PrfCryptoDemoSessionState.SessionReady }
            viewModel.onPlaintextChanged("private message")
            viewModel.onEncryptClicked()
            viewModel.uiState.first { !it.busy && it.sessionState == PrfCryptoDemoSessionState.CiphertextReady }
            viewModel.onDecryptClicked()
            viewModel.uiState.first { !it.busy && it.decryptedText != null }

            owner.clear()

            assertEquals(PrfCryptoDemoSessionState.NoSession, viewModel.uiState.value.sessionState)
            assertEquals("", viewModel.uiState.value.plaintext)
            assertEquals(null, viewModel.uiState.value.decryptedText)
            assertEquals(false, viewModel.uiState.value.busy)
        } finally {
            owner.clear()
            Dispatchers.resetMain()
        }
    }

    @Test
    fun disposing_owner_during_finish_rejects_non_cooperative_completion() = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        val owner = ViewModelStore()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        try {
            val backend = FakePrfBackend(finishAction = { _, _ ->
                withContext(NonCancellable) {
                    entered.complete(Unit)
                    release.await()
                }
                DefaultPasskeyFinishResult.Verified
            })
            val viewModel = mainViewModel(backend)
            owner.put("demo", viewModel)
            viewModel.uiState.first { it.supportsPrf }
            viewModel.onSignInWithPrfClicked()
            entered.await()

            owner.clear()
            release.complete(Unit)
            testScheduler.runCurrent()

            assertEquals(PrfCryptoDemoSessionState.NoSession, viewModel.uiState.value.sessionState)
            assertEquals(false, viewModel.uiState.value.busy)
        } finally {
            release.complete(Unit)
            owner.clear()
            Dispatchers.resetMain()
        }
    }

    private fun mainViewModel(backend: DemoPasskeyBackend = FakePrfBackend()) = MainViewModel(
        config = config(), debugLogs = DebugLogStore(), sessionStore = AppSessionStore(),
        saltStore = FixedSaltStore(), passkeyClient = FakePrfPasskeyClient(), backend = backend,
    )
}

private class FixedSaltStore : PrfSaltStore {
    private val salt = Base64UrlBytes.fromBytes(ByteArray(32) { 3 })
    val requestedKeys = mutableListOf<String>()

    override fun loadOrCreate(key: String): Base64UrlBytes {
        requestedKeys += key
        return salt
    }
}

private class FakePrfBackend(
    private val startAction: suspend (AuthenticationStartPayload) -> CeremonyStart<Unit, PublicKeyCredentialRequestOptions> = {
        CeremonyStart(Unit, defaultPrfOptions())
    },
    private val finishAction: suspend (Unit, RawAuthenticationResponse) -> DefaultPasskeyFinishResult = {
        _, _ -> DefaultPasskeyFinishResult.Verified
    },
) : DemoPasskeyBackend {
    var finishCalls: Int = 0
    var startCalls: Int = 0
    val startPayloads = mutableListOf<AuthenticationStartPayload>()
    override val registration: RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> =
        object : RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> {
            override suspend fun start(input: RegistrationStartPayload) = error("registration is not used")

            override suspend fun finish(
                state: Unit,
                response: RawRegistrationResponse,
            ): DefaultPasskeyFinishResult = error("registration is not used")
        }

    override val authentication: AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> =
        object : AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> {
            override suspend fun start(input: AuthenticationStartPayload) =
                startAction(input).also {
                    startCalls += 1
                    startPayloads += input
                }

            override suspend fun finish(
                state: Unit,
                response: RawAuthenticationResponse,
            ): DefaultPasskeyFinishResult {
                finishCalls += 1
                return finishAction(state, response)
            }
        }
}

private class FakePrfPasskeyClient(
    private val assertionResults: MutableList<PasskeyResult<RawAuthenticationResponse>> = mutableListOf(
        successfulAssertion(),
    ),
    private val beforeAssertion: suspend () -> Unit = {},
) : PasskeyClient {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RawRegistrationResponse> =
        error("registration is not used")

    var assertionCalls = 0

    override suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities(
        support = mapOf(PasskeyCapability.Extension(WebAuthnExtension.Prf) to CapabilitySupport.SUPPORTED),
    )

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<RawAuthenticationResponse> {
        assertionCalls += 1
        beforeAssertion()
        return assertionResults.removeAt(0)
    }
}

private fun controller(
    backend: DemoPasskeyBackend,
    passkeyClient: PasskeyClient = FakePrfPasskeyClient(),
    saltStore: PrfSaltStore = FixedSaltStore(),
    isForeground: () -> Boolean = { true },
): PrfCryptoDemoController = PrfCryptoDemoController(
    passkeyClient = passkeyClient,
    backend = backend,
    saltStore = saltStore,
    isForeground = isForeground,
)

private fun successfulAssertion(): PasskeyResult<RawAuthenticationResponse> = PasskeyResult.Success(
    RawAuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
        extensions = AuthenticationExtensionsClientOutputs(
            prf = PrfExtensionOutput(
                enabled = true,
                results = AuthenticationExtensionsPRFValues(
                    first = Base64UrlBytes.fromBytes(byteArrayOf(5, 4, 3, 2, 1)),
                ),
            ),
        ),
    ),
)

private fun defaultPrfOptions(): PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions(
    challenge = Challenge.fromBytes(ByteArray(32) { 9 }),
    rpId = RpId.parseOrThrow("example.test"),
)

private fun config(): PasskeyDemoConfig = PasskeyDemoConfig(
    endpointBase = "https://example.test",
    rpId = "example.test",
    origin = "https://example.test",
    userHandle = "demo-user-1",
    userName = "demo@local",
)
