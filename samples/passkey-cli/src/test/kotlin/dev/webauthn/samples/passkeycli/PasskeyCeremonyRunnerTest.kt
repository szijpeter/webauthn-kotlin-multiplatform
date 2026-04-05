package dev.webauthn.samples.passkeycli

import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.RegistrationResponseDto
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PasskeyCeremonyRunnerTest {
    @Test
    fun register_happyPath_finishesWithOriginalChallenge() = runTest {
        val serverClient = FakeServerClient(
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
            serverClient = serverClient,
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
        assertEquals(validRegisterOptions().challenge.value.encoded(), serverClient.lastRegisterChallenge)
        assertTrue(stdout.toString().contains("Registration verified"))
        assertTrue(stderr.isEmpty())
    }

    @Test
    fun authenticate_invalidAuthenticatorPayload_returnsFailureExitCode() = runTest {
        val invalidAuthResponse = validAuthenticationResponseDto().copy(
            response = validAuthenticationResponseDto().response.copy(signature = "not-base64url"),
        )
        val serverClient = FakeServerClient(
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
            serverClient = serverClient,
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
        val serverClient = FakeServerClient(
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
            serverClient = serverClient,
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

private class FakeServerClient(
    private val registerOptions: ValidationResult<PublicKeyCredentialCreationOptions>,
    private val authOptions: ValidationResult<PublicKeyCredentialRequestOptions>,
    private val finishRegisterResult: PasskeyFinishResult,
    private val finishSignInResult: PasskeyFinishResult,
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    var lastRegisterChallenge: String? = null

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> = registerOptions

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        lastRegisterChallenge = challengeAsBase64Url
        return finishRegisterResult
    }

    override suspend fun getSignInOptions(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> = authOptions

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = finishSignInResult
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
        pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                type = PublicKeyCredentialType.PUBLIC_KEY,
                alg = -7,
            ),
        ),
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
        endpointBase = "http://127.0.0.1:8080",
        rpId = "localhost",
        origin = "https://localhost",
        pythonBinary = "python3",
        pythonBridgePath = "samples/passkey-cli/scripts/fido2_bridge.py",
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
