package dev.webauthn.samples.composepasskey

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyClientError
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
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.network.kotlinx.RegistrationStartPayload
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyBackend
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.restore.RestoreCredentialDemoClient
import dev.webauthn.samples.composepasskey.domain.restore.RestoreCredentialDemoController
import dev.webauthn.samples.composepasskey.domain.restore.RestoreCredentialDemoResult
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class RestoreCredentialDemoControllerTest {
    @Test
    fun createRestoreCredential_forwards_raw_response_to_backend_finish() = runTest {
        val backend = RestoreFakeBackend()
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(restoreClient, backend)

        val result = controller.createRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Success>(result)
        assertTrue(result.message.contains("created"))
        assertEquals(1, restoreClient.createCalls)
        assertTrue(backend.registrationFinished)
        assertEquals(restoreValidRegistrationResponse(), backend.registrationResponse)
    }

    @Test
    fun getRestoreCredential_forwards_raw_response_to_backend_finish() = runTest {
        val backend = RestoreFakeBackend()
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(restoreClient, backend)

        val result = controller.getRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Success>(result)
        assertTrue(result.message.contains("verified"))
        assertEquals(1, restoreClient.getCalls)
        assertTrue(backend.authenticationFinished)
        assertEquals(restoreValidAuthenticationResponse(), backend.authenticationResponse)
    }

    @Test
    fun clearRestoreCredential_calls_platform_clear() = runTest {
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(restoreClient, RestoreFakeBackend())

        val result = controller.clearRestoreCredential()

        assertIs<RestoreCredentialDemoResult.Success>(result)
        assertEquals(1, restoreClient.clearCalls)
    }

    @Test
    fun createRestoreCredential_returns_platform_failure_without_finishing_or_clearing() = runTest {
        val backend = RestoreFakeBackend()
        val restoreClient = FakeRestoreCredentialClient(
            createResult = PasskeyResult.Failure(PasskeyClientError.Platform("create failed")),
        )
        val controller = RestoreCredentialDemoController(restoreClient, backend)

        val result = controller.createRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Failure>(result)
        assertTrue(result.message.contains("create failed"))
        assertEquals(0, backend.registrationFinishCalls)
        assertEquals(0, restoreClient.clearCalls)
    }

    @Test
    fun createRestoreCredential_clears_local_key_when_backend_rejects() = runTest {
        val backend = RestoreFakeBackend(
            registrationResult = DefaultPasskeyFinishResult.Rejected("server rejected"),
        )
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(restoreClient, backend)

        val result = controller.createRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Failure>(result)
        assertEquals("server rejected", result.message)
        assertEquals(1, restoreClient.clearCalls)
    }

    @Test
    fun createRestoreCredential_reports_rejection_and_cleanup_failure() = runTest {
        val backend = RestoreFakeBackend(
            registrationResult = DefaultPasskeyFinishResult.Rejected("server rejected"),
        )
        val restoreClient = FakeRestoreCredentialClient(
            clearResult = PasskeyResult.Failure(PasskeyClientError.Platform("clear failed")),
        )
        val controller = RestoreCredentialDemoController(restoreClient, backend)

        val result = controller.createRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Failure>(result)
        assertTrue(result.message.contains("server rejected"))
        assertTrue(result.message.contains("clear failed"))
        assertEquals(1, restoreClient.clearCalls)
    }

    @Test
    fun createRestoreCredential_clears_local_key_when_backend_finish_throws() = runTest {
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(
            restoreClient,
            RestoreFakeBackend(registrationFailure = IllegalStateException("backend unavailable")),
        )

        val result = controller.createRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Failure>(result)
        assertTrue(result.message.contains("backend unavailable"))
        assertEquals(1, restoreClient.clearCalls)
    }
}

private class FakeRestoreCredentialClient(
    private val createResult: PasskeyResult<RawRegistrationResponse> =
        PasskeyResult.Success(restoreValidRegistrationResponse()),
    private val clearResult: PasskeyResult<Unit> = PasskeyResult.Success(Unit),
) : RestoreCredentialDemoClient {
    var createCalls: Int = 0
    var getCalls: Int = 0
    var clearCalls: Int = 0

    override val isAvailable: Boolean = true

    override suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean,
    ): PasskeyResult<RawRegistrationResponse> {
        createCalls += 1
        return createResult
    }

    override suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<RawAuthenticationResponse> {
        getCalls += 1
        return PasskeyResult.Success(restoreValidAuthenticationResponse())
    }

    override suspend fun clearRestoreCredential(): PasskeyResult<Unit> {
        clearCalls += 1
        return clearResult
    }
}

private class RestoreFakeBackend(
    private val registrationResult: DefaultPasskeyFinishResult = DefaultPasskeyFinishResult.Verified,
    private val registrationFailure: Throwable? = null,
) : DemoPasskeyBackend {
    var registrationFinished: Boolean = false
    var registrationFinishCalls: Int = 0
    var authenticationFinished: Boolean = false
    var registrationResponse: RawRegistrationResponse? = null
    var authenticationResponse: RawAuthenticationResponse? = null

    override val registration = object :
        RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult> {
        override suspend fun start(
            input: RegistrationStartPayload,
        ): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> =
            CeremonyStart(Unit, restoreValidCreationOptions())

        override suspend fun finish(
            state: Unit,
            response: RawRegistrationResponse,
        ): DefaultPasskeyFinishResult {
            registrationFinishCalls += 1
            registrationFailure?.let { throw it }
            registrationFinished = true
            registrationResponse = response
            return registrationResult
        }
    }

    override val authentication = object :
        AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult> {
        override suspend fun start(
            input: AuthenticationStartPayload,
        ): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> =
            CeremonyStart(Unit, restoreValidRequestOptions())

        override suspend fun finish(
            state: Unit,
            response: RawAuthenticationResponse,
        ): DefaultPasskeyFinishResult {
            authenticationFinished = true
            authenticationResponse = response
            return DefaultPasskeyFinishResult.Verified
        }
    }
}

private fun restoreValidDemoConfig(): PasskeyDemoConfig = PasskeyDemoConfig(
    endpointBase = "https://example.test",
    rpId = "example.test",
    origin = "https://example.test",
    userHandle = "demo-user-1",
    userName = "demo@local",
)

private fun restoreValidCreationOptions(): PublicKeyCredentialCreationOptions =
    PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
        user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
        challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
        pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),
        ),
    )

private fun restoreValidRequestOptions(): PublicKeyCredentialRequestOptions =
    PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
        rpId = RpId.parseOrThrow("example.com"),
    )

private fun restoreValidRegistrationResponse(): RawRegistrationResponse = RawRegistrationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
    attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
)

private fun restoreValidAuthenticationResponse(): RawAuthenticationResponse = RawAuthenticationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
    authenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 4 }),
    signature = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
)
