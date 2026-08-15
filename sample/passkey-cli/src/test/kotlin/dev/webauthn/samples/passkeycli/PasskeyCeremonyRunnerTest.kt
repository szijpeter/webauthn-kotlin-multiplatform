package dev.webauthn.samples.passkeycli

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.RegistrationResponseDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PasskeyCeremonyRunnerTest {
    @Test
    fun register_happyPath_finishesThroughTypedBackend() = runTest {
        val backends = FakeServerBackends(
            registerOptions = ValidationResult.Valid(validRegisterOptions()),
            authOptions = ValidationResult.Valid(validAuthenticationOptions()),
            finishRegisterResult = PasskeyFinishResult.Verified,
            finishSignInResult = PasskeyFinishResult.Verified,
        )
        val adapter = FakeAuthenticatorAdapter(
            registrationResponse = validRegistrationResponseDto(),
            authenticationResponse = validAuthenticationResponseDto(),
        )
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val runner = PasskeyCeremonyRunner(
            authenticatorAdapter = adapter,
            registrationBackend = backends.registrationBackend,
            authenticationBackend = backends.authenticationBackend,
            stdout = stdout,
            stderr = stderr,
        )

        val exitCode = runner.runRegister(
            CliInvocation.Register(
                common = defaultCommonOptions(),
                userName = "alice",
                userDisplayName = "Alice",
                userHandle = "YWxpY2U",
            ),
        )

        assertEquals(0, exitCode)
        assertEquals(1, backends.registrationFinishCalls)
        assertTrue(stdout.toString().contains("Registration verified"))
        assertTrue(stderr.isEmpty())
    }

    @Test
    fun authenticate_invalidAuthenticatorPayload_returnsFailureExitCode() = runTest {
        val invalidAuthResponse = validAuthenticationResponseDto().copy(
            response = validAuthenticationResponseDto().response.copy(signature = "not-base64url"),
        )
        val backends = FakeServerBackends(
            registerOptions = ValidationResult.Valid(validRegisterOptions()),
            authOptions = ValidationResult.Valid(validAuthenticationOptions()),
            finishRegisterResult = PasskeyFinishResult.Verified,
            finishSignInResult = PasskeyFinishResult.Verified,
        )
        val adapter = FakeAuthenticatorAdapter(
            registrationResponse = validRegistrationResponseDto(),
            authenticationResponse = invalidAuthResponse,
        )
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val runner = PasskeyCeremonyRunner(
            authenticatorAdapter = adapter,
            registrationBackend = backends.registrationBackend,
            authenticationBackend = backends.authenticationBackend,
            stdout = stdout,
            stderr = stderr,
        )

        val exitCode = runner.runAuthenticate(
            CliInvocation.Authenticate(
                common = defaultCommonOptions(),
                userName = "alice",
                userHandle = null,
            ),
        )

        assertNotEquals(0, exitCode)
        assertTrue(stderr.toString().contains("failed validation"))
    }

    @Test
    fun register_rejectedWithoutMessage_usesSafeFallbackText() = runTest {
        val backends = FakeServerBackends(
            registerOptions = ValidationResult.Valid(validRegisterOptions()),
            authOptions = ValidationResult.Valid(validAuthenticationOptions()),
            finishRegisterResult = PasskeyFinishResult.Rejected(),
            finishSignInResult = PasskeyFinishResult.Verified,
        )
        val adapter = FakeAuthenticatorAdapter(
            registrationResponse = validRegistrationResponseDto(),
            authenticationResponse = validAuthenticationResponseDto(),
        )
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val runner = PasskeyCeremonyRunner(
            authenticatorAdapter = adapter,
            registrationBackend = backends.registrationBackend,
            authenticationBackend = backends.authenticationBackend,
            stdout = stdout,
            stderr = stderr,
        )

        val exitCode = runner.runRegister(
            CliInvocation.Register(
                common = defaultCommonOptions(),
                userName = "alice",
                userDisplayName = "Alice",
                userHandle = "YWxpY2U",
            ),
        )

        assertEquals(5, exitCode)
        assertTrue(stderr.toString().contains("no reason provided"))
        assertFalse(stderr.toString().contains("null"))
    }

    @Test
    fun register_whenStartIsCancelled_rethrowsCancellationException() = runTest {
        val adapter = FakeAuthenticatorAdapter(
            registrationResponse = validRegistrationResponseDto(),
            authenticationResponse = validAuthenticationResponseDto(),
        )
        val runner = PasskeyCeremonyRunner(
            authenticatorAdapter = adapter,
            registrationBackend = CancellationRegistrationBackend(),
            authenticationBackend = UnusedAuthenticationBackend(),
            stdout = StringBuilder(),
            stderr = StringBuilder(),
        )

        assertFailsWith<CancellationException> {
            runner.runRegister(
                CliInvocation.Register(
                    common = defaultCommonOptions(),
                    userName = "alice",
                    userDisplayName = "Alice",
                    userHandle = "YWxpY2U",
                ),
            )
        }
    }
}

private class FakeAuthenticatorAdapter(
    private val registrationResponse: RegistrationResponseDto,
    private val authenticationResponse: AuthenticationResponseDto,
) : AuthenticatorAdapter {
    override suspend fun createCredential(
        origin: String,
        options: dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto,
    ): RegistrationResponseDto = registrationResponse

    override suspend fun getAssertion(
        origin: String,
        options: dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto,
    ): AuthenticationResponseDto = authenticationResponse
}

private class FakeServerBackends(
    private val registerOptions: ValidationResult<PublicKeyCredentialCreationOptions>,
    private val authOptions: ValidationResult<PublicKeyCredentialRequestOptions>,
    private val finishRegisterResult: PasskeyFinishResult,
    private val finishSignInResult: PasskeyFinishResult,
) {
    var registrationFinishCalls: Int = 0

    val registrationBackend = object : RegistrationBackend<RegistrationStartPayload, Unit, PasskeyFinishResult> {
        override suspend fun start(
            input: RegistrationStartPayload,
        ): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> = CeremonyStart(
            state = Unit,
            options = registerOptions.orThrow("registration"),
        )

        override suspend fun finish(state: Unit, response: RawRegistrationResponse): PasskeyFinishResult {
            registrationFinishCalls += 1
            return finishRegisterResult
        }
    }

    val authenticationBackend = object : AuthenticationBackend<AuthenticationStartPayload, Unit, PasskeyFinishResult> {
        override suspend fun start(
            input: AuthenticationStartPayload,
        ): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> = CeremonyStart(
            state = Unit,
            options = authOptions.orThrow("authentication"),
        )

        override suspend fun finish(state: Unit, response: RawAuthenticationResponse): PasskeyFinishResult =
            finishSignInResult
    }
}

private class CancellationRegistrationBackend :
    RegistrationBackend<RegistrationStartPayload, Unit, PasskeyFinishResult> {
    override suspend fun start(
        input: RegistrationStartPayload,
    ): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> {
        throw CancellationException("simulated cancellation")
    }

    override suspend fun finish(state: Unit, response: RawRegistrationResponse): PasskeyFinishResult =
        PasskeyFinishResult.Verified
}

private class UnusedAuthenticationBackend :
    AuthenticationBackend<AuthenticationStartPayload, Unit, PasskeyFinishResult> {
    override suspend fun start(
        input: AuthenticationStartPayload,
    ): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> {
        throw UnsupportedOperationException("not used")
    }

    override suspend fun finish(state: Unit, response: RawAuthenticationResponse): PasskeyFinishResult {
        throw UnsupportedOperationException("not used")
    }
}

private fun <T> ValidationResult<T>.orThrow(operation: String): T = when (this) {
    is ValidationResult.Valid -> value
    is ValidationResult.Invalid -> error("$operation options are invalid")
}

private fun validRegisterOptions(): PublicKeyCredentialCreationOptions {
    return PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(
            id = RpId.parseOrThrow("localhost"),
            name = "localhost",
        ),
        user = PublicKeyCredentialUserEntity(
            id = UserHandle.fromBytes(byteArrayOf(1, 2, 3)),
            name = "alice",
            displayName = "Alice",
        ),
        challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
        pubKeyCredParams = [
            PublicKeyCredentialParameters(
                type = PublicKeyCredentialType.PUBLIC_KEY,
                alg = -7,
            ),
        ],
    )
}

private fun validAuthenticationOptions(): PublicKeyCredentialRequestOptions {
    return PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
        rpId = RpId.parseOrThrow("localhost"),
    )
}

private fun defaultCommonOptions(): CommonCliOptions {
    return CommonCliOptions(
        endpointBase = "http://localhost:8080",
        rpId = "localhost",
        origin = "http://localhost:8080",
        authenticatorMode = AuthenticatorMode.BROWSER,
        pythonBinary = "python3",
        pythonBridgePath = "sample/passkey-cli/scripts/fido2_bridge.py",
    )
}

private fun validRegistrationResponseDto(): RegistrationResponseDto {
    val json = Json { ignoreUnknownKeys = true }
    return json.decodeFromString(
        RegistrationResponseDto.serializer(),
        """
        {
          "id": "MzMzMzMzMzMzMzMzMzMzMw",
          "rawId": "MzMzMzMzMzMzMzMzMzMzMw",
          "response": {
            "clientDataJSON": "BAUG",
            "attestationObject": "o2NmbXRkbm9uZWhhdXRoRGF0YVhKRERERERERERERERERERERERERERERERERERERERERERBAAAACVVVVVVVVVVVVVVVVVVVVVUAEDMzMzMzMzMzMzMzMzMzMzOhAQJnYXR0U3RtdKA"
          }
        }
        """.trimIndent(),
    )
}

private fun validAuthenticationResponseDto(): AuthenticationResponseDto {
    val json = Json { ignoreUnknownKeys = true }
    return json.decodeFromString(
        AuthenticationResponseDto.serializer(),
        """
        {
          "id": "MzMzMzMzMzMzMzMzMzMzMw",
          "rawId": "MzMzMzMzMzMzMzMzMzMzMw",
          "response": {
            "clientDataJSON": "AQID",
            "authenticatorData": "REREREREREREREREREREREREREREREREREREREREREQFAAAAKg",
            "signature": "CQkJ"
          }
        }
        """.trimIndent(),
    )
}
