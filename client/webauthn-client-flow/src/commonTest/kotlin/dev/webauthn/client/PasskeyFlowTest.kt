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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class PasskeyFlowTest {
    @Test
    fun registration_preserves_raw_response_and_opaque_state() = runTest {
        val raw = rawRegistration()
        val phases = mutableListOf<PasskeyPhase>()
        val flow = PasskeyFlow(TestClient(createResult = PasskeyResult.Success(raw)))
        val backend = object : RegistrationBackend<String, String, String> {
            override suspend fun start(input: String) = CeremonyStart("continuation:$input", creationOptions())

            override suspend fun finish(state: String, response: RawRegistrationResponse): String {
                assertEquals("continuation:user", state)
                assertEquals(raw, response)
                return "registered"
            }
        }

        val result = flow.register("user", backend, phases::add)

        assertEquals(CeremonyResult.Success("registered"), result)
        assertEquals(
            listOf(PasskeyPhase.STARTING, PasskeyPhase.PLATFORM_PROMPT, PasskeyPhase.FINISHING),
            phases,
        )
    }

    @Test
    fun authentication_preserves_raw_response_and_opaque_state() = runTest {
        val raw = rawAuthentication()
        val flow = PasskeyFlow(TestClient(assertionResult = PasskeyResult.Success(raw)))
        val backend = object : AuthenticationBackend<Unit, Int, Int> {
            override suspend fun start(input: Unit) = CeremonyStart(42, requestOptions())

            override suspend fun finish(state: Int, response: RawAuthenticationResponse): Int {
                assertEquals(42, state)
                assertEquals(raw, response)
                return 7
            }
        }

        assertEquals(CeremonyResult.Success(7), flow.signIn(Unit, backend))
    }

    @Test
    fun registration_forwards_conditional_create_options() = runTest {
        val client = TestClient(createResult = PasskeyResult.Success(rawRegistration()))
        val flow = PasskeyFlow(client)

        val result = flow.register(
            input = "user",
            backend = registrationBackend(),
            createOptions = PasskeyCreateOptions.Conditional,
        )

        assertIs<CeremonyResult.Success<Unit>>(result)
        assertEquals(PasskeyCreateOptions.Conditional, client.receivedCreateOptions)
    }

    @Test
    fun platform_failure_is_classified_but_backend_failure_propagates() = runTest {
        val platformError = PasskeyClientError.UserCancelled()
        val flow = PasskeyFlow(TestClient(createResult = PasskeyResult.Failure(platformError)))
        val platformResult = flow.register("input", registrationBackend())
        assertEquals(CeremonyResult.Failure(CeremonyFailure.Platform(platformError)), platformResult)

        val backendFailure = IllegalStateException("backend down")
        val throwingBackend = object : RegistrationBackend<String, Unit, Unit> {
            override suspend fun start(input: String): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> =
                throw backendFailure

            override suspend fun finish(state: Unit, response: RawRegistrationResponse) = Unit
        }
        assertEquals(backendFailure, assertFailsWith<IllegalStateException> {
            flow.register("input", throwingBackend)
        })
    }

    @Test
    fun concurrent_ceremony_is_rejected_and_lock_is_released() = runTest {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val client = TestClient(createAction = {
            entered.complete(Unit)
            release.await()
            PasskeyResult.Success(rawRegistration())
        })
        val flow = PasskeyFlow(client)
        val backend = registrationBackend()
        val first = async { flow.register("first", backend) }
        entered.await()

        assertEquals(
            CeremonyResult.Failure(CeremonyFailure.AlreadyInProgress),
            flow.register("second", backend),
        )
        release.complete(Unit)
        assertIs<CeremonyResult.Success<Unit>>(first.await())
        assertIs<CeremonyResult.Success<Unit>>(flow.register("third", backend))
    }

    @Test
    fun callback_and_finish_exceptions_propagate() = runTest {
        val flow = PasskeyFlow(TestClient(createResult = PasskeyResult.Success(rawRegistration())))
        val callbackFailure = IllegalArgumentException("callback")
        assertEquals(callbackFailure, assertFailsWith<IllegalArgumentException> {
            flow.register("input", registrationBackend(), onPhaseChanged = { throw callbackFailure })
        })

        val finishFailure = IllegalStateException("finish")
        val backend = object : RegistrationBackend<String, Unit, Unit> {
            override suspend fun start(input: String) = CeremonyStart(Unit, creationOptions())
            override suspend fun finish(state: Unit, response: RawRegistrationResponse): Unit = throw finishFailure
        }
        assertEquals(finishFailure, assertFailsWith<IllegalStateException> { flow.register("input", backend) })
    }

    private fun registrationBackend() = object : RegistrationBackend<String, Unit, Unit> {
        override suspend fun start(input: String) = CeremonyStart(Unit, creationOptions())
        override suspend fun finish(state: Unit, response: RawRegistrationResponse) = Unit
    }
}

private class TestClient(
    private val createResult: PasskeyResult<RawRegistrationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    private val assertionResult: PasskeyResult<RawAuthenticationResponse> = PasskeyResult.Failure(PasskeyClientError.Platform("unused")),
    private val createAction: (suspend () -> PasskeyResult<RawRegistrationResponse>)? = null,
) : PasskeyClient {
    var receivedCreateOptions: PasskeyCreateOptions? = null

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RawRegistrationResponse> =
        createAction?.invoke() ?: createResult

    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
        createOptions: PasskeyCreateOptions,
    ): PasskeyResult<RawRegistrationResponse> {
        receivedCreateOptions = createOptions
        return createAction?.invoke() ?: createResult
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<RawAuthenticationResponse> =
        assertionResult
}

private fun creationOptions() = PublicKeyCredentialCreationOptions(
    rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
    user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "user", "User"),
    challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
    pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7)),
)

private fun requestOptions() = PublicKeyCredentialRequestOptions(
    challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
    rpId = RpId.parseOrThrow("example.com"),
)

private fun rawRegistration() = RawRegistrationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(1, 2)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(3)),
    attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4)),
)

private fun rawAuthentication() = RawAuthenticationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(1, 2)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(3)),
    authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4)),
    signature = Base64UrlBytes.fromBytes(byteArrayOf(5)),
)
