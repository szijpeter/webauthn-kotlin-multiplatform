package dev.webauthn.client

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class PasskeyControllerTest {

    @Test
    fun register_ceremony_transitions_through_all_phases_to_success() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient(
            createResult = PasskeyResult.Success(validRegistrationResponse()),
        )
        val serverClient = FakePasskeyServerClient()
        val controller = PasskeyController(passkeyClient = fakeClient, serverClient = serverClient)

        assertEquals(PasskeyControllerState.Idle, controller.uiState.value)

        val job = launch {
            controller.register(Unit)
        }

        // Before returning options, state should be STARTING
        assertEquals(
            PasskeyControllerState.InProgress(PasskeyAction.REGISTER, ControllerPhase.STARTING),
            controller.uiState.value,
        )

        serverClient.registerOptionsDeferred.complete(ValidationResult.Valid(validCreationOptions()))

        // After returning options, but before platform finishes (Platform finishes instantly because it's synchronous fake),
        // we then enter FINISHING phase because getOptions and platform are done.
        assertEquals(
            PasskeyControllerState.InProgress(PasskeyAction.REGISTER, ControllerPhase.FINISHING),
            controller.uiState.value,
        )

        serverClient.finishRegisterDeferred.complete(PasskeyFinishResult.Verified)

        // After finish, state should be Success
        assertEquals(
            PasskeyControllerState.Success(PasskeyAction.REGISTER),
            controller.uiState.value,
        )

        job.join()
    }

    @Test
    fun options_validation_failure_transitions_to_error() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient()
        val serverClient = FakePasskeyServerClient()
        serverClient.registerOptionsDeferred.complete(
            ValidationResult.Invalid([WebAuthnValidationError.InvalidValue("field", "bad options")])
        )
        val controller = PasskeyController(fakeClient, serverClient)

        controller.register(Unit)

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.InvalidOptions>(finalState.error)
        assertTrue(finalState.error.message.contains("bad options"))
    }

    @Test
    fun platform_failure_transitions_to_error() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient(
            createResult = PasskeyResult.Failure(PasskeyClientError.UserCancelled("cancelled by user"))
        )
        val serverClient = FakePasskeyServerClient()
        serverClient.registerOptionsDeferred.complete(ValidationResult.Valid(validCreationOptions()))
        val controller = PasskeyController(fakeClient, serverClient)

        controller.register(Unit)

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.UserCancelled>(finalState.error)
    }

    @Test
    fun finish_rejected_result_transitions_to_transport_error() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient(
            createResult = PasskeyResult.Success(validRegistrationResponse())
        )
        val serverClient = FakePasskeyServerClient()
        serverClient.registerOptionsDeferred.complete(ValidationResult.Valid(validCreationOptions()))
        serverClient.finishRegisterDeferred.complete(PasskeyFinishResult.Rejected())
        val controller = PasskeyController(fakeClient, serverClient)

        controller.register(Unit)

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.Transport>(finalState.error)
        assertTrue(finalState.error.message.contains("rejected by the server"))
    }

    @Test
    fun server_exception_maps_to_transport_error() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient()
        val serverClient = FakePasskeyServerClient(
            signInOptionsException = IllegalStateException("random crash")
        )
        val controller = PasskeyController(fakeClient, serverClient)

        controller.signIn(Unit)

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.Transport>(finalState.error)
        assertTrue(finalState.error.message.contains("random crash"))
    }

    @Test
    fun concurrent_actions_prevented() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient()
        val serverClient = FakePasskeyServerClient()
        val controller = PasskeyController(fakeClient, serverClient)

        val firstJob = launch {
            controller.signIn(Unit)
        }

        // State is now STARTING
        assertEquals(PasskeyControllerState.InProgress(PasskeyAction.SIGN_IN, ControllerPhase.STARTING), controller.uiState.value)

        // Try to register concurrently
        controller.register(Unit)

        // State should remain SIGN_IN STARTING without throwing exception out of runCeremony, but the register loop silently aborted.
        assertEquals(PasskeyControllerState.InProgress(PasskeyAction.SIGN_IN, ControllerPhase.STARTING), controller.uiState.value)

        serverClient.signInOptionsDeferred.complete(ValidationResult.Invalid(emptyList()))
        firstJob.join()
    }

    @Test
    fun cancellation_resets_state_to_idle() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient()
        val serverClient = FakePasskeyServerClient()
        val controller = PasskeyController(fakeClient, serverClient)

        val job = launch {
            controller.signIn(Unit)
        }

        assertEquals(
            PasskeyControllerState.InProgress(PasskeyAction.SIGN_IN, ControllerPhase.STARTING),
            controller.uiState.value,
        )

        job.cancel()
        job.join()

        assertEquals(PasskeyControllerState.Idle, controller.uiState.value)
    }

    private class FakePasskeyServerClient(
        val registerOptionsDeferred: CompletableDeferred<ValidationResult<PublicKeyCredentialCreationOptions>> = CompletableDeferred(),
        val finishRegisterDeferred: CompletableDeferred<PasskeyFinishResult> = CompletableDeferred(),
        val signInOptionsDeferred: CompletableDeferred<ValidationResult<PublicKeyCredentialRequestOptions>> = CompletableDeferred(),
        val finishSignInDeferred: CompletableDeferred<PasskeyFinishResult> = CompletableDeferred(),
        val signInOptionsException: Throwable? = null,
    ) : PasskeyServerClient<Unit, Unit> {
        override suspend fun getRegisterOptions(params: Unit): ValidationResult<PublicKeyCredentialCreationOptions> = registerOptionsDeferred.await()
        override suspend fun finishRegister(
            params: Unit,
            response: RawRegistrationResponse,
            challengeAsBase64Url: String,
        ): PasskeyFinishResult = finishRegisterDeferred.await()
        override suspend fun getSignInOptions(params: Unit): ValidationResult<PublicKeyCredentialRequestOptions> {
            signInOptionsException?.let { throw it }
            return signInOptionsDeferred.await()
        }
        override suspend fun finishSignIn(
            params: Unit,
            response: RawAuthenticationResponse,
            challengeAsBase64Url: String,
        ): PasskeyFinishResult = finishSignInDeferred.await()
    }

    private class FakePasskeyClient(
        private val createResult: PasskeyResult<RawRegistrationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
        private val assertionResult: PasskeyResult<RawAuthenticationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RawRegistrationResponse> = createResult
        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<RawAuthenticationResponse> = assertionResult
    }

    private companion object {
        fun validCreationOptions(): PublicKeyCredentialCreationOptions {
            return PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
                pubKeyCredParams = [
                    PublicKeyCredentialParameters(type = PublicKeyCredentialType.PUBLIC_KEY, alg = -7),
                ],
            )
        }

        fun validRegistrationResponse(): RawRegistrationResponse {
            return RawRegistrationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
            )
        }
    }
}
