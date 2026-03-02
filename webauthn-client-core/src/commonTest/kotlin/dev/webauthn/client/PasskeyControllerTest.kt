package dev.webauthn.client

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PasskeyControllerTest {

    @Test
    fun register_ceremony_transitions_through_all_phases_to_success() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient(
            createResult = PasskeyResult.Success(validRegistrationResponse()),
        )
        val controller = PasskeyController(passkeyClient = fakeClient)

        assertEquals(PasskeyControllerState.Idle, controller.uiState.value)

        val deferredOptions = CompletableDeferred<ValidationResult<PublicKeyCredentialCreationOptions>>()
        val deferredFinish = CompletableDeferred<Boolean>()

        val job = launch {
            controller.register(
                getOptions = { deferredOptions.await() },
                finish = { _, _ -> deferredFinish.await() },
            )
        }

        // Before returning options, state should be STARTING
        assertEquals(
            PasskeyControllerState.InProgress(PasskeyAction.REGISTER, PasskeyPhase.STARTING),
            controller.uiState.value,
        )

        deferredOptions.complete(ValidationResult.Valid(validCreationOptions(), emptyList()))

        // After returning options, but before platform finishes (Platform finishes instantly because it's synchronous fake),
        // we then enter FINISHING phase because getOptions and platform are done.
        assertEquals(
            PasskeyControllerState.InProgress(PasskeyAction.REGISTER, PasskeyPhase.FINISHING),
            controller.uiState.value,
        )

        deferredFinish.complete(true)

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
        val controller = PasskeyController(fakeClient)

        controller.register(
            getOptions = { 
                ValidationResult.Invalid(null, listOf(dev.webauthn.model.ValidationError("field", "bad options"))) 
            },
            finish = { _, _ -> true },
        )

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
        val controller = PasskeyController(fakeClient)

        controller.register(
            getOptions = { ValidationResult.Valid(validCreationOptions(), emptyList()) },
            finish = { _, _ -> true },
        )

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.UserCancelled>(finalState.error)
    }

    @Test
    fun finish_returning_false_transitions_to_transport_error() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient(
            createResult = PasskeyResult.Success(validRegistrationResponse())
        )
        val controller = PasskeyController(fakeClient)

        controller.register(
            getOptions = { ValidationResult.Valid(validCreationOptions(), emptyList()) },
            finish = { _, _ -> false }, // Backend rejects logic
        )

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.Transport>(finalState.error)
        assertTrue(finalState.error.message.contains("rejected by the server"))
    }

    @Test
    fun unknown_exception_is_wrapped() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient()
        val controller = PasskeyController(fakeClient)

        controller.signIn(
            getOptions = { throw IllegalStateException("random crash") },
            finish = { _, _ -> true },
        )

        val finalState = controller.uiState.value
        assertIs<PasskeyControllerState.Failure>(finalState)
        assertIs<PasskeyClientError.Platform>(finalState.error)
        assertTrue(finalState.error.message.contains("random crash"))
    }

    @Test
    fun concurrent_actions_prevented() = runTest(UnconfinedTestDispatcher()) {
        val fakeClient = FakePasskeyClient()
        val controller = PasskeyController(fakeClient)
        
        val deferredOptions = CompletableDeferred<ValidationResult<PublicKeyCredentialRequestOptions>>()
        
        val firstJob = launch {
            controller.signIn(getOptions = { deferredOptions.await() }, finish = { _, _ -> true })
        }

        // State is now STARTING
        assertEquals(PasskeyControllerState.InProgress(PasskeyAction.SIGN_IN, PasskeyPhase.STARTING), controller.uiState.value)

        // Try to register concurrently
        controller.register(
            getOptions = { ValidationResult.Valid(validCreationOptions(), emptyList()) },
            finish = { _, _ -> true }
        )
        
        // State should remain SIGN_IN STARTING without throwing exception out of runCeremony, but the register loop silently aborted.
        assertEquals(PasskeyControllerState.InProgress(PasskeyAction.SIGN_IN, PasskeyPhase.STARTING), controller.uiState.value)

        deferredOptions.complete(ValidationResult.Invalid(null, listOf()))
        firstJob.join()
    }

    private class FakePasskeyClient(
        private val createResult: PasskeyResult<RegistrationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
        private val assertionResult: PasskeyResult<AuthenticationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> = createResult
        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> = assertionResult
    }

    private companion object {
        fun validCreationOptions(): PublicKeyCredentialCreationOptions {
            return PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
                pubKeyCredParams = listOf(
                    PublicKeyCredentialParameters(type = PublicKeyCredentialType.PUBLIC_KEY, alg = -7),
                ),
            )
        }

        fun validRegistrationResponse(): RegistrationResponse {
            return RegistrationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
                rawAuthenticatorData = AuthenticatorData(rpIdHash = ByteArray(32) { 1 }, flags = 0x41, signCount = 1),
                attestedCredentialData = AttestedCredentialData(aaguid = ByteArray(16) { 2 }, credentialId = CredentialId.fromBytes(byteArrayOf(9, 9, 9)), cosePublicKey = byteArrayOf(1, 2, 3)),
            )
        }
    }
}
