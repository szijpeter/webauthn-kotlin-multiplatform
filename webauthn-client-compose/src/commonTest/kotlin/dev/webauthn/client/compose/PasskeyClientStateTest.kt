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
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PasskeyClientStateTest {
    @Test
    fun createCredential_updatesStateToSuccess() = runTest {
        val state = PasskeyClientState(
            passkeyClient = FakePasskeyClient(
                createResult = PasskeyResult.Success(validRegistrationResponse()),
            ),
        )

        val result = state.createCredential(validCreationOptions())

        assertTrue(result is PasskeyResult.Success)
        assertFalse(state.uiState.isBusy)
        assertEquals(PasskeyOperation.CREATE_CREDENTIAL, state.uiState.lastSuccess)
        assertNull(state.uiState.lastError)
    }

    @Test
    fun getAssertion_updatesStateToFailure() = runTest {
        val error = PasskeyClientError.UserCancelled()
        val state = PasskeyClientState(
            passkeyClient = FakePasskeyClient(
                assertionResult = PasskeyResult.Failure(error),
            ),
        )

        val result = state.getAssertion(validRequestOptions())

        assertTrue(result is PasskeyResult.Failure)
        assertFalse(state.uiState.isBusy)
        assertEquals(error, state.uiState.lastError)
        assertNull(state.uiState.activeOperation)
    }

    private class FakePasskeyClient(
        private val createResult: PasskeyResult<RegistrationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
        private val assertionResult: PasskeyResult<AuthenticationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
            return createResult
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
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
