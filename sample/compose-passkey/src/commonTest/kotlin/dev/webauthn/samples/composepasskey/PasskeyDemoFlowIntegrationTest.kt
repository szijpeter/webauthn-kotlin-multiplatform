package dev.webauthn.samples.composepasskey

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyFailure
import dev.webauthn.client.CeremonyResult
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyFlow
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.RegistrationBackend
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
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.yield
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class PasskeyDemoFlowIntegrationTest {
    @Test
    fun registration_carries_opaque_state_to_typed_finish_output() = runTest {
        val client = FakePasskeyClient()
        val flow = PasskeyFlow(client)
        val phases = mutableListOf<dev.webauthn.client.PasskeyPhase>()
        val backend = object : RegistrationBackend<Unit, String, String> {
            override suspend fun start(input: Unit): CeremonyStart<String, PublicKeyCredentialCreationOptions> =
                CeremonyStart("continuation-42", validCreationOptions())

            override suspend fun finish(state: String, response: RawRegistrationResponse): String {
                assertEquals("continuation-42", state)
                assertEquals(client.registrationResponse, response)
                return "application-output"
            }
        }

        val result = flow.register(Unit, backend, onPhaseChanged = phases::add)

        assertEquals(CeremonyResult.Success("application-output"), result)
        assertEquals(
            listOf(
                dev.webauthn.client.PasskeyPhase.STARTING,
                dev.webauthn.client.PasskeyPhase.PLATFORM_PROMPT,
                dev.webauthn.client.PasskeyPhase.FINISHING,
            ),
            phases,
        )
    }

    @Test
    fun platform_failure_is_classified_without_collapsing_backend_errors() = runTest {
        val flow = PasskeyFlow(FakePasskeyClient(
            registrationResult = PasskeyResult.Failure(PasskeyClientError.UserCancelled()),
        ))
        val backend = object : RegistrationBackend<Unit, Unit, String> {
            override suspend fun start(input: Unit): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> =
                CeremonyStart(Unit, validCreationOptions())

            override suspend fun finish(state: Unit, response: RawRegistrationResponse): String = "unused"
        }

        val result = flow.register(Unit, backend)

        val failure = assertIs<CeremonyResult.Failure>(result)
        assertEquals(CeremonyFailure.Platform(PasskeyClientError.UserCancelled()), failure.error)
    }

    @Test
    fun concurrent_ceremony_is_rejected_while_first_backend_is_running() = runTest {
        val flow = PasskeyFlow(FakePasskeyClient())
        val backend = object : AuthenticationBackend<Unit, Unit, String> {
            override suspend fun start(input: Unit): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> {
                delay(100)
                return CeremonyStart(Unit, validRequestOptions())
            }

            override suspend fun finish(state: Unit, response: RawAuthenticationResponse): String = "ok"
        }

        val first = async { flow.signIn(Unit, backend) }
        yield()
        val second = flow.signIn(Unit, backend)

        assertEquals(CeremonyResult.Failure(CeremonyFailure.AlreadyInProgress), second)
        assertEquals(CeremonyResult.Success("ok"), first.await())
    }
}

private class FakePasskeyClient(
    val registrationResponse: RawRegistrationResponse = validRegistrationResponse(),
    private val registrationResult: PasskeyResult<RawRegistrationResponse> =
        PasskeyResult.Success(registrationResponse),
) : PasskeyClient {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RawRegistrationResponse> =
        registrationResult

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<RawAuthenticationResponse> =
        PasskeyResult.Success(validAuthenticationResponse())
}

private fun validCreationOptions(): PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions(
    rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.test"), "Example"),
    user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
    challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
    pubKeyCredParams = listOf(
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),
    ),
)

private fun validRequestOptions(): PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions(
    challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
    rpId = RpId.parseOrThrow("example.test"),
)

private fun validRegistrationResponse(): RawRegistrationResponse = RawRegistrationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
    attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
)

private fun validAuthenticationResponse(): RawAuthenticationResponse = RawAuthenticationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
    authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
    signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)),
)
