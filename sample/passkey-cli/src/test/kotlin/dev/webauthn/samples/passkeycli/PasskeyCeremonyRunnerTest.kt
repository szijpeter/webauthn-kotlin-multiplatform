package dev.webauthn.samples.passkeycli

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.Challenge
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
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.network.kotlinx.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PasskeyCeremonyRunnerTest {
    @Test
    fun registration_success_returns_success_exit() = runTest {
        val stdout = StringBuilder()
        val code = runner(stdout = stdout).runRegister(registerCommand())

        assertEquals(0, code)
        assertTrue(stdout.contains("Registration verified"))
    }

    @Test
    fun authentication_success_returns_success_exit() = runTest {
        val stdout = StringBuilder()
        val code = runner(stdout = stdout).runAuthenticate(authenticateCommand())

        assertEquals(0, code)
        assertTrue(stdout.contains("Authentication verified"))
    }

    @Test
    fun invalid_registration_response_returns_adapter_exit() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            adapter = FakeAuthenticatorAdapter(
                registration = { _, _ -> validRegistrationResponseDto().copy(rawId = "!") },
            ),
            stderr = stderr,
        ).runRegister(registerCommand())

        assertEquals(3, code)
        assertTrue(stderr.contains("Native registration response failed validation"))
        assertTrue(stderr.contains("credentialId"))
    }

    @Test
    fun invalid_authentication_response_returns_adapter_exit() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            adapter = FakeAuthenticatorAdapter(
                authentication = { _, _ -> validAuthenticationResponseDto().copy(rawId = "!") },
            ),
            stderr = stderr,
        ).runAuthenticate(authenticateCommand())

        assertEquals(3, code)
        assertTrue(stderr.contains("Native authentication response failed validation"))
        assertTrue(stderr.contains("credentialId"))
    }

    @Test
    fun backend_start_failure_returns_options_exit_and_does_not_prompt() = runTest {
        var promptCalls = 0
        val stderr = StringBuilder()
        val code = runner(
            backends = FakeBackends(
                registrationStart = { error("backend unavailable") },
            ),
            adapter = FakeAuthenticatorAdapter(
                registration = { _, _ ->
                    promptCalls += 1
                    error("prompt must not run")
                },
            ),
            stderr = stderr,
        ).runRegister(registerCommand())

        assertEquals(2, code)
        assertEquals(0, promptCalls)
        assertTrue(stderr.contains("backend unavailable"))
    }

    @Test
    fun backend_finish_rejection_without_message_uses_safe_fallback() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            backends = FakeBackends(
                registrationFinish = { _, _ -> DefaultPasskeyFinishResult.Rejected() },
            ),
            stderr = stderr,
        ).runRegister(registerCommand())

        assertEquals(5, code)
        assertTrue(stderr.contains("no reason provided"))
    }

    @Test
    fun authentication_finish_rejection_without_message_uses_safe_fallback() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            backends = FakeBackends(
                authenticationFinish = { _, _ -> DefaultPasskeyFinishResult.Rejected() },
            ),
            stderr = stderr,
        ).runAuthenticate(authenticateCommand())

        assertEquals(5, code)
        assertTrue(stderr.contains("no reason provided"))
    }

    @Test
    fun backend_finish_exception_returns_finish_exit() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            backends = FakeBackends(
                registrationFinish = { _, _ -> error("finish unavailable") },
            ),
            stderr = stderr,
        ).runRegister(registerCommand())

        assertEquals(4, code)
        assertTrue(stderr.contains("finish unavailable"))
    }

    @Test
    fun authentication_finish_exception_returns_finish_exit() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            backends = FakeBackends(
                authenticationFinish = { _, _ -> error("finish unavailable") },
            ),
            stderr = stderr,
        ).runAuthenticate(authenticateCommand())

        assertEquals(4, code)
        assertTrue(stderr.contains("finish unavailable"))
    }

    @Test
    fun authenticator_exception_returns_adapter_exit() = runTest {
        val stderr = StringBuilder()
        val code = runner(
            adapter = FakeAuthenticatorAdapter(
                registration = { _, _ -> error("prompt unavailable") },
            ),
            stderr = stderr,
        ).runRegister(registerCommand())

        assertEquals(3, code)
        assertTrue(stderr.contains("prompt unavailable"))
    }

    @Test
    fun backend_start_cancellation_propagates() = runTest {
        val error = assertFailsWith<CancellationException> {
            runner(
                backends = FakeBackends(
                    registrationStart = { throw CancellationException("start cancelled") },
                ),
            ).runRegister(registerCommand())
        }

        assertEquals("start cancelled", error.message)
    }

    @Test
    fun authenticator_cancellation_propagates() = runTest {
        val error = assertFailsWith<CancellationException> {
            runner(
                adapter = FakeAuthenticatorAdapter(
                    registration = { _, _ -> throw CancellationException("prompt cancelled") },
                ),
            ).runRegister(registerCommand())
        }

        assertEquals("prompt cancelled", error.message)
    }

    @Test
    fun backend_finish_cancellation_propagates() = runTest {
        val error = assertFailsWith<CancellationException> {
            runner(
                backends = FakeBackends(
                    registrationFinish = { _, _ -> throw CancellationException("finish cancelled") },
                ),
            ).runRegister(registerCommand())
        }

        assertEquals("finish cancelled", error.message)
    }

    @Test
    fun usage_errors_are_still_reported_by_the_cli_parser() = runTest {
        val stderr = StringBuilder()
        val code = CliApplication(stdout = StringBuilder(), stderr = stderr).run(
            arrayOf("register", "--rp-id", "example.test"),
        )

        assertEquals(EXIT_PARSE_USAGE, code)
        assertTrue(stderr.contains("Usage"))
    }
}

private class FakeBackends(
    private val registrationStart: suspend (RegistrationStartPayload) ->
        CeremonyStart<Unit, PublicKeyCredentialCreationOptions> = {
        CeremonyStart(Unit, creationOptions())
    },
    private val registrationFinish: suspend (Unit, RawRegistrationResponse) ->
        DefaultPasskeyFinishResult = { _, _ -> DefaultPasskeyFinishResult.Verified },
    private val authenticationStart: suspend (AuthenticationStartPayload) ->
        CeremonyStart<Unit, PublicKeyCredentialRequestOptions> = {
        CeremonyStart(Unit, requestOptions())
    },
    private val authenticationFinish: suspend (Unit, RawAuthenticationResponse) ->
        DefaultPasskeyFinishResult = { _, _ -> DefaultPasskeyFinishResult.Verified },
) {
    val registration: RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> =
        object : RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> {
            override suspend fun start(input: RegistrationStartPayload) = registrationStart(input)

            override suspend fun finish(state: Unit, response: RawRegistrationResponse) =
                registrationFinish(state, response)
        }

    val authentication: AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> =
        object : AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> {
            override suspend fun start(input: AuthenticationStartPayload) = authenticationStart(input)

            override suspend fun finish(state: Unit, response: RawAuthenticationResponse) =
                authenticationFinish(state, response)
        }
}

private class FakeAuthenticatorAdapter(
    private val registration: suspend (String, PublicKeyCredentialCreationOptionsDto) -> RegistrationResponseDto = {
            _, _ -> validRegistrationResponseDto()
        },
    private val authentication: suspend (String, PublicKeyCredentialRequestOptionsDto) -> AuthenticationResponseDto = {
            _, _ -> validAuthenticationResponseDto()
        },
) : AuthenticatorAdapter {
    override suspend fun createCredential(
        origin: String,
        options: PublicKeyCredentialCreationOptionsDto,
    ): RegistrationResponseDto = registration(origin, options)

    override suspend fun getAssertion(
        origin: String,
        options: PublicKeyCredentialRequestOptionsDto,
    ): AuthenticationResponseDto = authentication(origin, options)
}

private fun runner(
    backends: FakeBackends = FakeBackends(),
    adapter: AuthenticatorAdapter = FakeAuthenticatorAdapter(),
    stdout: Appendable = StringBuilder(),
    stderr: Appendable = StringBuilder(),
) = PasskeyCeremonyRunner(adapter, backends.registration, backends.authentication, stdout, stderr)

private fun registerCommand() = CliInvocation.Register(
    common = commonOptions(),
    userName = "alice",
    userDisplayName = "Alice",
    userHandle = "AQID",
)

private fun authenticateCommand() = CliInvocation.Authenticate(
    common = commonOptions(),
    userName = "alice",
    userHandle = null,
)

private fun commonOptions() = CommonCliOptions(
    endpointBase = "https://example.test",
    rpId = "example.test",
    origin = "https://example.test",
    authenticatorMode = AuthenticatorMode.BROWSER,
    pythonBinary = "python3",
    pythonBridgePath = "bridge.py",
)

private fun creationOptions() = PublicKeyCredentialCreationOptions(
    rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.test"), "Example"),
    user = PublicKeyCredentialUserEntity(
        UserHandle.fromBytes(byteArrayOf(1, 2, 3)),
        "alice",
        "Alice",
    ),
    challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
    pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7)),
)

private fun requestOptions() = PublicKeyCredentialRequestOptions(
    challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
    rpId = RpId.parseOrThrow("example.test"),
)

private fun validRegistrationResponseDto() = RegistrationResponseDto(
    id = "MzMzMzMzMzMzMzMzMzMzMw",
    rawId = "MzMzMzMzMzMzMzMzMzMzMw",
    response = RegistrationResponsePayloadDto(
        clientDataJson = "BAUG",
        attestationObject =
            "o2NmbXRkbm9uZWhhdXRoRGF0YVhKRERERERERERERERERERERERERERERERERERERERERERBAAAACVVVVVVVVVVVVVVVVVVVVVUAEDMzMzMzMzMzMzMzMzMzMzOhAQJnYXR0U3RtdKA",
    ),
)

private fun validAuthenticationResponseDto() = AuthenticationResponseDto(
    id = "MzMzMzMzMzMzMzMzMzMzMw",
    rawId = "MzMzMzMzMzMzMzMzMzMzMw",
    response = AuthenticationResponsePayloadDto(
        clientDataJson = "AQID",
        authenticatorData = "REREREREREREREREREREREREREREREREREREREREREQFAAAAKg",
        signature = "CQkJ",
    ),
)
