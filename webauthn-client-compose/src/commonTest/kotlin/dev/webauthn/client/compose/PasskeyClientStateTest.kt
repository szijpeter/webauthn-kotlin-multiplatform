package dev.webauthn.client.compose

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
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
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class PasskeyClientStateTest {
    @Test
    fun register_lifecycle_transitions_to_success() = runTest {
        val state = PasskeyClientState(
            passkeyClient = FakePasskeyClient(
                createResult = PasskeyResult.Success(validRegistrationResponse()),
            ),
        )

        state.begin(PasskeyAction.REGISTER)
        assertEquals(
            PasskeyClientUiState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.STARTING,
            ),
            state.uiState,
        )
        state.setPhase(PasskeyAction.REGISTER, PasskeyPhase.PLATFORM_PROMPT)

        val result = state.createCredential(validCreationOptions())
        assertTrue(result is PasskeyResult.Success)
        state.setPhase(PasskeyAction.REGISTER, PasskeyPhase.FINISHING)
        state.finishSuccess(PasskeyAction.REGISTER)

        assertEquals(PasskeyClientUiState.Success(PasskeyAction.REGISTER), state.uiState)
    }

    @Test
    fun invalid_transition_rejected_when_action_does_not_match_in_progress() {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())
        state.begin(PasskeyAction.REGISTER)

        assertFailsWith<IllegalStateException> {
            state.setPhase(PasskeyAction.SIGN_IN, PasskeyPhase.PLATFORM_PROMPT)
        }
    }

    @Test
    fun begin_rejected_while_another_operation_is_active() {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())
        state.begin(PasskeyAction.REGISTER)

        assertFailsWith<IllegalStateException> {
            state.begin(PasskeyAction.SIGN_IN)
        }
    }

    @Test
    fun terminal_state_persists_until_next_action_or_reset() {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())

        state.begin(PasskeyAction.REGISTER)
        state.finishSuccess(PasskeyAction.REGISTER)
        assertEquals(PasskeyClientUiState.Success(PasskeyAction.REGISTER), state.uiState)

        state.begin(PasskeyAction.SIGN_IN)
        assertEquals(
            PasskeyClientUiState.InProgress(
                action = PasskeyAction.SIGN_IN,
                phase = PasskeyPhase.STARTING,
            ),
            state.uiState,
        )

        state.finishFailure(PasskeyAction.SIGN_IN, PasskeyClientError.UserCancelled())
        assertIs<PasskeyClientUiState.Failure>(state.uiState)

        state.resetToIdle()
        assertEquals(PasskeyClientUiState.Idle, state.uiState)
    }

    @Test
    fun create_credential_throwable_is_mapped_and_can_finish_failure() = runTest {
        val state = PasskeyClientState(
            passkeyClient = FakePasskeyClient(
                createThrowable = IllegalStateException("platform prompt failed"),
            ),
        )

        state.begin(PasskeyAction.REGISTER)
        state.setPhase(PasskeyAction.REGISTER, PasskeyPhase.PLATFORM_PROMPT)
        val result = state.createCredential(validCreationOptions())
        val failure = assertIs<PasskeyResult.Failure>(result)
        val error = failure.error
        assertTrue(error is PasskeyClientError.Platform)
        assertTrue(error.message.contains("platform prompt failed"))

        state.finishFailure(PasskeyAction.REGISTER, error)
        assertEquals(
            PasskeyClientUiState.Failure(
                action = PasskeyAction.REGISTER,
                error = error,
            ),
            state.uiState,
        )
    }

    private class FakePasskeyClient(
        private val createResult: PasskeyResult<RegistrationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
        private val assertionResult: PasskeyResult<AuthenticationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
        private val createThrowable: Throwable? = null,
        private val assertionThrowable: Throwable? = null,
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
            createThrowable?.let { throw it }
            return createResult
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
            assertionThrowable?.let { throw it }
            return assertionResult
        }

        override suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
    }

    private companion object {
        fun validCreationOptions(): PublicKeyCredentialCreationOptions {
            return PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
                pubKeyCredParams = listOf(
                    PublicKeyCredentialParameters(
                        type = PublicKeyCredentialType.PUBLIC_KEY,
                        alg = -7,
                    ),
                ),
            )
        }

        fun validRequestOptions(): PublicKeyCredentialRequestOptions {
            return PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
            )
        }

        fun validRegistrationResponse(): RegistrationResponse {
            return RegistrationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
                rawAuthenticatorData = AuthenticatorData(
                    rpIdHash = ByteArray(32) { 1 },
                    flags = 0x41,
                    signCount = 1,
                ),
                attestedCredentialData = AttestedCredentialData(
                    aaguid = ByteArray(16) { 2 },
                    credentialId = CredentialId.fromBytes(byteArrayOf(9, 9, 9)),
                    cosePublicKey = byteArrayOf(1, 2, 3),
                ),
            )
        }
    }
}
