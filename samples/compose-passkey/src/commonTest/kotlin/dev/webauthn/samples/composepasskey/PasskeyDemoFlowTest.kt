package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.compose.PasskeyAction
import dev.webauthn.client.compose.PasskeyClientState
import dev.webauthn.client.compose.PasskeyClientUiState
import dev.webauthn.client.compose.PasskeyPhase
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
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PasskeyDemoFlowTest {
    @Test
    fun register_success_updates_state_to_success_register() = runTest {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())
        val backend = FakeBackend()

        runRegisterCeremony(
            config = PasskeyDemoConfig(endpointBase = "https://example.test"),
            passkeyClientState = state,
            backend = backend,
            diagnostics = TestDiagnostics(),
        )

        assertEquals(PasskeyClientUiState.Success(PasskeyAction.REGISTER), state.uiState)
    }

    @Test
    fun sign_in_success_updates_state_to_success_sign_in() = runTest {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())
        val backend = FakeBackend()

        runSignInCeremony(
            config = PasskeyDemoConfig(endpointBase = "https://example.test"),
            passkeyClientState = state,
            backend = backend,
            diagnostics = TestDiagnostics(),
        )

        assertEquals(PasskeyClientUiState.Success(PasskeyAction.SIGN_IN), state.uiState)
    }

    @Test
    fun register_start_validation_failure_ends_in_invalid_options() = runTest {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())
        val backend = FakeBackend(
            registrationStartResult = ValidationResult.Invalid(
                errors = listOf(WebAuthnValidationError.MissingValue(field = "challenge", message = "missing")),
            ),
        )

        runRegisterCeremony(
            config = PasskeyDemoConfig(endpointBase = "https://example.test"),
            passkeyClientState = state,
            backend = backend,
            diagnostics = TestDiagnostics(),
        )

        val failure = assertIs<PasskeyClientUiState.Failure>(state.uiState)
        assertEquals(PasskeyAction.REGISTER, failure.action)
        assertTrue(failure.error is PasskeyClientError.InvalidOptions)
        assertTrue(failure.error.message.contains("challenge"))
    }

    @Test
    fun register_verify_rejection_ends_in_transport_failure() = runTest {
        val state = PasskeyClientState(passkeyClient = FakePasskeyClient())
        val backend = FakeBackend(registrationVerifyResult = false)

        runRegisterCeremony(
            config = PasskeyDemoConfig(endpointBase = "https://example.test"),
            passkeyClientState = state,
            backend = backend,
            diagnostics = TestDiagnostics(),
        )

        val failure = assertIs<PasskeyClientUiState.Failure>(state.uiState)
        assertEquals(PasskeyAction.REGISTER, failure.action)
        assertTrue(failure.error is PasskeyClientError.Transport)
    }

    @Test
    fun action_buttons_disabled_only_while_in_progress() {
        assertTrue(areCeremonyActionsEnabled(PasskeyClientUiState.Idle))
        assertFalse(
            areCeremonyActionsEnabled(
                PasskeyClientUiState.InProgress(
                    action = PasskeyAction.REGISTER,
                    phase = PasskeyPhase.STARTING,
                ),
            ),
        )
        assertTrue(areCeremonyActionsEnabled(PasskeyClientUiState.Success(PasskeyAction.SIGN_IN)))
    }

    @Test
    fun timeline_entries_are_emitted_for_start_and_terminal_transitions() {
        val started = timelineEntryForTransition(
            previous = PasskeyClientUiState.Idle,
            current = PasskeyClientUiState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.STARTING,
            ),
            id = 1L,
            timestamp = "t+1s",
        )
        val completed = timelineEntryForTransition(
            previous = PasskeyClientUiState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.FINISHING,
            ),
            current = PasskeyClientUiState.Success(PasskeyAction.REGISTER),
            id = 2L,
            timestamp = "t+2s",
        )

        assertEquals(StatusTone.WORKING, started?.tone)
        assertTrue(started?.message.orEmpty().contains("started"))
        assertEquals(StatusTone.SUCCESS, completed?.tone)
        assertTrue(completed?.message.orEmpty().contains("completed"))
    }
}

private class FakeBackend(
    private val registrationStartResult: ValidationResult<PublicKeyCredentialCreationOptions> = ValidationResult.Valid(validCreationOptions()),
    private val registrationVerifyResult: Boolean = true,
    private val authenticationStartResult: ValidationResult<PublicKeyCredentialRequestOptions> = ValidationResult.Valid(validRequestOptions()),
    private val authenticationVerifyResult: Boolean = true,
) : PasskeyDemoBackend {
    override suspend fun startRegistration(config: PasskeyDemoConfig): ValidationResult<PublicKeyCredentialCreationOptions> {
        return registrationStartResult
    }

    override suspend fun finishRegistration(
        config: PasskeyDemoConfig,
        response: RegistrationResponse,
        challenge: String,
    ): Boolean {
        return registrationVerifyResult
    }

    override suspend fun startAuthentication(config: PasskeyDemoConfig): ValidationResult<PublicKeyCredentialRequestOptions> {
        return authenticationStartResult
    }

    override suspend fun finishAuthentication(
        config: PasskeyDemoConfig,
        response: AuthenticationResponse,
        challenge: String,
    ): Boolean {
        return authenticationVerifyResult
    }
}

private class FakePasskeyClient(
    private val createResult: PasskeyResult<RegistrationResponse> = PasskeyResult.Success(validRegistrationResponse()),
    private val assertionResult: PasskeyResult<AuthenticationResponse> = PasskeyResult.Success(validAuthenticationResponse()),
) : PasskeyClient {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return createResult
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return assertionResult
    }

    override suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
}

private class TestDiagnostics : PasskeyDemoDiagnostics {
    override fun trace(event: String, fields: Map<String, String>) = Unit

    override fun error(
        event: String,
        message: String,
        throwable: Throwable?,
        fields: Map<String, String>,
    ) = Unit
}

private fun validCreationOptions(): PublicKeyCredentialCreationOptions {
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

private fun validRequestOptions(): PublicKeyCredentialRequestOptions {
    return PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
        rpId = RpId.parseOrThrow("example.com"),
    )
}

private fun validRegistrationResponse(): RegistrationResponse {
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

private fun validAuthenticationResponse(): AuthenticationResponse {
    return AuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        rawAuthenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        authenticatorData = AuthenticatorData(
            rpIdHash = ByteArray(32) { 1 },
            flags = 0x01,
            signCount = 2,
        ),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
    )
}
