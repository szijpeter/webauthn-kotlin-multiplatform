package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.Aaguid
import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.areCeremonyActionsEnabled
import dev.webauthn.samples.composepasskey.domain.passkey.controllerTransitionEvent
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PasskeyDemoFlowTest {
    @Test
    fun request_payloads_normalize_plaintext_user_handle_to_base64url() {
        val config = validDemoConfig()
        val expected = Base64UrlBytes.fromBytes("demo-user-1".encodeToByteArray()).encoded()

        val registrationPayload = config.toRegistrationStartPayload()
        val authenticationPayload = config.toAuthenticationStartPayload()

        assertEquals(expected, registrationPayload.userHandle)
        assertEquals("required", registrationPayload.residentKey)
        assertEquals(null, authenticationPayload.userName)
    }

    @Test
    fun request_payloads_preserve_existing_base64url_user_handle() {
        val config = validDemoConfig().copy(userHandle = "AQID")

        val registrationPayload = config.toRegistrationStartPayload()
        val authenticationPayload = config.toAuthenticationStartPayload()

        assertEquals("AQID", registrationPayload.userHandle)
        assertEquals("required", registrationPayload.residentKey)
        assertEquals(null, authenticationPayload.userName)
    }

    @Test
    fun request_payloads_include_prf_extension_when_salt_provided() {
        val config = validDemoConfig()
        val salt = Base64UrlBytes.fromBytes(ByteArray(32) { 7 })

        val authenticationPayload = config.toAuthenticationStartPayload(prfSalt = salt)

        assertEquals(
            salt.encoded(),
            authenticationPayload.extensions?.prf?.eval?.first,
        )
    }

    @Test
    fun register_success_updates_state_to_success_register() = runTest {
        val controller = createController()

        controller.register(validDemoConfig().toRegistrationStartPayload())

        assertEquals(PasskeyControllerState.Success(PasskeyAction.REGISTER), controller.uiState.value)
    }

    @Test
    fun sign_in_success_updates_state_to_success_sign_in() = runTest {
        val controller = createController()

        controller.signIn(validDemoConfig().toAuthenticationStartPayload())

        assertEquals(PasskeyControllerState.Success(PasskeyAction.SIGN_IN), controller.uiState.value)
    }

    @Test
    fun register_start_validation_failure_ends_in_invalid_options() = runTest {
        val controller = createController(
            serverClient = FakeServerClient(
                registerOptions = ValidationResult.Invalid(
                    errors = listOf(WebAuthnValidationError.MissingValue(field = "challenge", message = "missing")),
                ),
            ),
        )

        controller.register(validDemoConfig().toRegistrationStartPayload())

        val failure = assertIs<PasskeyControllerState.Failure>(controller.uiState.value)
        assertEquals(PasskeyAction.REGISTER, failure.action)
        assertIs<PasskeyClientError.InvalidOptions>(failure.error)
        assertTrue(failure.error.message.contains("challenge"))
    }

    @Test
    fun register_verify_rejection_ends_in_transport_failure() = runTest {
        val controller = createController(
            serverClient = FakeServerClient(registerVerifyResult = false),
        )

        controller.register(validDemoConfig().toRegistrationStartPayload())

        val failure = assertIs<PasskeyControllerState.Failure>(controller.uiState.value)
        assertEquals(PasskeyAction.REGISTER, failure.action)
        assertIs<PasskeyClientError.Transport>(failure.error)
    }

    @Test
    fun action_buttons_disabled_only_while_in_progress() {
        assertTrue(areCeremonyActionsEnabled(PasskeyControllerState.Idle))
        assertFalse(
            areCeremonyActionsEnabled(
                PasskeyControllerState.InProgress(
                    action = PasskeyAction.REGISTER,
                    phase = PasskeyPhase.STARTING,
                ),
            ),
        )
        assertTrue(areCeremonyActionsEnabled(PasskeyControllerState.Success(PasskeyAction.SIGN_IN)))
    }

    @Test
    fun controller_transition_events_cover_start_success_and_failure() {
        val started = controllerTransitionEvent(
            previous = PasskeyControllerState.Idle,
            current = PasskeyControllerState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.STARTING,
            ),
        )
        val completed = controllerTransitionEvent(
            previous = PasskeyControllerState.InProgress(
                action = PasskeyAction.REGISTER,
                phase = PasskeyPhase.FINISHING,
            ),
            current = PasskeyControllerState.Success(PasskeyAction.REGISTER),
        )
        val failed = controllerTransitionEvent(
            previous = PasskeyControllerState.InProgress(
                action = PasskeyAction.SIGN_IN,
                phase = PasskeyPhase.PLATFORM_PROMPT,
            ),
            current = PasskeyControllerState.Failure(
                action = PasskeyAction.SIGN_IN,
                error = PasskeyClientError.UserCancelled("cancelled"),
            ),
        )

        assertEquals(DebugLogLevel.INFO, started?.level)
        assertTrue(started?.message.orEmpty().contains("starting"))
        assertEquals(DebugLogLevel.INFO, completed?.level)
        assertTrue(completed?.message.orEmpty().contains("success"))
        assertEquals(DebugLogLevel.WARN, failed?.level)
        assertTrue(failed?.message.orEmpty().contains("failed"))
    }

    private fun createController(
        passkeyClient: PasskeyClient = FakePasskeyClient(),
        serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> = FakeServerClient(),
    ): PasskeyController<RegistrationStartPayload, AuthenticationStartPayload> {
        return PasskeyController(passkeyClient = passkeyClient, serverClient = serverClient)
    }
}

private class FakeServerClient(
    private val registerOptions: ValidationResult<PublicKeyCredentialCreationOptions> = ValidationResult.Valid(validCreationOptions()),
    private val registerVerifyResult: Boolean = true,
    private val signInOptions: ValidationResult<PublicKeyCredentialRequestOptions> = ValidationResult.Valid(validRequestOptions()),
    private val signInVerifyResult: Boolean = true,
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    override suspend fun getRegisterOptions(params: RegistrationStartPayload): ValidationResult<PublicKeyCredentialCreationOptions> {
        return registerOptions
    }

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        return if (registerVerifyResult) {
            PasskeyFinishResult.Verified
        } else {
            PasskeyFinishResult.Rejected()
        }
    }

    override suspend fun getSignInOptions(params: AuthenticationStartPayload): ValidationResult<PublicKeyCredentialRequestOptions> {
        return signInOptions
    }

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        return if (signInVerifyResult) {
            PasskeyFinishResult.Verified
        } else {
            PasskeyFinishResult.Rejected()
        }
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
}

private fun validDemoConfig(): PasskeyDemoConfig {
    return PasskeyDemoConfig(
        endpointBase = "https://example.test",
        rpId = "example.test",
        origin = "https://example.test",
        userHandle = "demo-user-1",
        userName = "demo@local",
    )
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
            rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 1 }),
            flags = 0x41,
            signCount = 1,
        ),
        attestedCredentialData = AttestedCredentialData(
            aaguid = Aaguid.fromBytes(ByteArray(16) { 2 }),
            credentialId = CredentialId.fromBytes(byteArrayOf(9, 9, 9)),
            cosePublicKey = CosePublicKey.fromBytes(byteArrayOf(1, 2, 3)),
        ),
    )
}

private fun validAuthenticationResponse(): AuthenticationResponse {
    return AuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        rawAuthenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        authenticatorData = AuthenticatorData(
            rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 1 }),
            flags = 0x01,
            signCount = 2,
        ),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
    )
}
