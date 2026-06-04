package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyFinishResult
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
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
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
    fun createRestoreCredential_finishes_registration_with_server() = runTest {
        val serverClient = RestoreFakeServerClient()
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(
            restoreCredentialClient = restoreClient,
            serverClient = serverClient,
        )

        val result = controller.createRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Success>(result)
        assertTrue(result.message.contains("created"))
        assertEquals(1, restoreClient.createCalls)
        assertEquals("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", serverClient.finishedRegisterChallenge)
    }

    @Test
    fun getRestoreCredential_finishes_sign_in_with_server() = runTest {
        val serverClient = RestoreFakeServerClient()
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(
            restoreCredentialClient = restoreClient,
            serverClient = serverClient,
        )

        val result = controller.getRestoreCredential(restoreValidDemoConfig())

        assertIs<RestoreCredentialDemoResult.Success>(result)
        assertTrue(result.message.contains("verified"))
        assertEquals(1, restoreClient.getCalls)
        assertEquals("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", serverClient.finishedSignInChallenge)
    }

    @Test
    fun clearRestoreCredential_calls_platform_clear() = runTest {
        val restoreClient = FakeRestoreCredentialClient()
        val controller = RestoreCredentialDemoController(
            restoreCredentialClient = restoreClient,
            serverClient = RestoreFakeServerClient(),
        )

        val result = controller.clearRestoreCredential()

        assertIs<RestoreCredentialDemoResult.Success>(result)
        assertEquals(1, restoreClient.clearCalls)
    }
}

private class FakeRestoreCredentialClient : RestoreCredentialDemoClient {
    var createCalls: Int = 0
    var getCalls: Int = 0
    var clearCalls: Int = 0

    override val isAvailable: Boolean = true

    override suspend fun createRestoreCredential(
        options: PublicKeyCredentialCreationOptions,
        isCloudBackupEnabled: Boolean,
    ): PasskeyResult<RegistrationResponse> {
        createCalls += 1
        return PasskeyResult.Success(restoreValidRegistrationResponse())
    }

    override suspend fun getRestoreCredential(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        getCalls += 1
        return PasskeyResult.Success(restoreValidAuthenticationResponse())
    }

    override suspend fun clearRestoreCredential(): PasskeyResult<Unit> {
        clearCalls += 1
        return PasskeyResult.Success(Unit)
    }
}

private class RestoreFakeServerClient : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    var finishedRegisterChallenge: String? = null
    var finishedSignInChallenge: String? = null

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        return ValidationResult.Valid(restoreValidCreationOptions())
    }

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        finishedRegisterChallenge = challengeAsBase64Url
        return PasskeyFinishResult.Verified
    }

    override suspend fun getSignInOptions(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        return ValidationResult.Valid(restoreValidRequestOptions())
    }

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        finishedSignInChallenge = challengeAsBase64Url
        return PasskeyFinishResult.Verified
    }
}

private fun restoreValidDemoConfig(): PasskeyDemoConfig {
    return PasskeyDemoConfig(
        endpointBase = "https://example.test",
        rpId = "example.test",
        origin = "https://example.test",
        userHandle = "demo-user-1",
        userName = "demo@local",
    )
}

private fun restoreValidCreationOptions(): PublicKeyCredentialCreationOptions {
    return PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
        user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1, 2, 3)), "alice", "Alice"),
        challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
        pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                -7,
            ),
        ),
    )
}

private fun restoreValidRequestOptions(): PublicKeyCredentialRequestOptions {
    return PublicKeyCredentialRequestOptions(
        challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
        rpId = RpId.parseOrThrow("example.com"),
    )
}

private fun restoreValidRegistrationResponse(): RegistrationResponse {
    return RegistrationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        rawAuthenticatorData = AuthenticatorData(
            rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 4 }),
            flags = 0,
            signCount = 0,
        ),
        attestedCredentialData = AttestedCredentialData(
            aaguid = Aaguid.fromBytes(ByteArray(16)),
            credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
            cosePublicKey = CosePublicKey.fromBytes(byteArrayOf(1, 2, 3)),
        ),
    )
}

private fun restoreValidAuthenticationResponse(): AuthenticationResponse {
    val rawAuthenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 4 })
    return AuthenticationResponse(
        credentialId = CredentialId.fromBytes(byteArrayOf(7, 7, 7)),
        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
        rawAuthenticatorData = rawAuthenticatorData,
        authenticatorData = AuthenticatorData(
            rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 4 }),
            flags = 0,
            signCount = 0,
        ),
        signature = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
        userHandle = null,
    )
}
