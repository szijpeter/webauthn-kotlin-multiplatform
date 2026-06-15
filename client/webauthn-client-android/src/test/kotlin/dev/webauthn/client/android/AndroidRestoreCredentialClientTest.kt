package dev.webauthn.client.android

import android.content.Context
import android.os.Bundle
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateRestoreCredentialRequest
import androidx.credentials.CreateRestoreCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetRestoreCredentialOption
import androidx.credentials.RestoreCredential
import androidx.credentials.exceptions.restorecredential.E2eeUnavailableException
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidRestoreCredentialClientTest {
    @Test
    fun createRestoreCredential_forwards_restore_request_and_decodes_registration_response() = runBlocking {
        val request = slot<CreateCredentialRequest>()
        val credentialManager = mockk<CredentialManager>(relaxed = true)
        coEvery {
            credentialManager.createCredential(any<Context>(), capture(request))
        } returns CreateRestoreCredentialResponse(VALID_REGISTRATION_RESPONSE_JSON)
        val client = testClient(credentialManager)

        val result = client.createRestoreCredential(
            options = creationOptions(),
            isCloudBackupEnabled = false,
        )

        assertTrue("Expected Success but was $result", result is PasskeyResult.Success)
        val success = result as PasskeyResult.Success
        assertEquals("adnJdzQQOzHT8aobzfRCfA", success.value.credentialId.value.encoded())
        val restoreRequest = request.captured as CreateRestoreCredentialRequest
        assertEquals(false, restoreRequest.isCloudBackupEnabled)
        assertTrue(restoreRequest.requestJson.contains("\"rp\""))
    }

    @Test
    fun getRestoreCredential_forwards_single_restore_option_and_decodes_authentication_response() = runBlocking {
        val request = slot<GetCredentialRequest>()
        val credentialManager = mockk<CredentialManager>(relaxed = true)
        coEvery {
            credentialManager.getCredential(any<Context>(), capture(request))
        } returns GetCredentialResponse(restoreCredential(VALID_AUTHENTICATION_RESPONSE_JSON))
        val client = testClient(credentialManager)

        val result = client.getRestoreCredential(requestOptions())

        assertTrue("Expected Success but was $result", result is PasskeyResult.Success)
        val success = result as PasskeyResult.Success
        assertEquals("MzMzMzMzMzMzMzMzMzMzMw", success.value.credentialId.value.encoded())
        val options = request.captured.credentialOptions
        assertEquals(1, options.size)
        assertTrue(options.single() is GetRestoreCredentialOption)
    }

    @Test
    fun clearRestoreCredential_sends_restore_clear_request() = runBlocking {
        val request = slot<ClearCredentialStateRequest>()
        val credentialManager = mockk<CredentialManager>(relaxed = true)
        coEvery { credentialManager.clearCredentialState(capture(request)) } returns Unit
        val client = testClient(credentialManager)

        val result = client.clearRestoreCredential()

        assertTrue("Expected Success but was $result", result is PasskeyResult.Success)
        assertEquals(ClearCredentialStateRequest.TYPE_CLEAR_RESTORE_CREDENTIAL, request.captured.requestType)
        coVerify(exactly = 1) { credentialManager.clearCredentialState(any()) }
    }

    @Test
    fun createRestoreCredential_maps_e2ee_unavailable_to_platform_failure() = runBlocking {
        val credentialManager = mockk<CredentialManager>(relaxed = true)
        coEvery {
            credentialManager.createCredential(any<Context>(), any<CreateRestoreCredentialRequest>())
        } throws E2eeUnavailableException("backup unavailable")
        val client = testClient(credentialManager)

        val result = client.createRestoreCredential(creationOptions())

        assertTrue(result is PasskeyResult.Failure)
        val failure = result as PasskeyResult.Failure
        assertTrue(failure.error is PasskeyClientError.Platform)
        assertTrue(failure.error.message.contains("backup unavailable"))
    }

    private fun testClient(credentialManager: CredentialManager): AndroidRestoreCredentialClient {
        return AndroidRestoreCredentialClient(
            context = mockk(relaxed = true),
            credentialManagerFactory = { credentialManager },
        )
    }

    private fun creationOptions(): PublicKeyCredentialCreationOptions {
        return PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
            user = PublicKeyCredentialUserEntity(
                id = UserHandle.fromBytes(byteArrayOf(1)),
                name = "demo@example.com",
                displayName = "Demo User",
            ),
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            pubKeyCredParams = listOf(
                PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),
            ),
        )
    }

    private fun requestOptions(): PublicKeyCredentialRequestOptions {
        return PublicKeyCredentialRequestOptions(
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            rpId = RpId.parseOrThrow("example.com"),
        )
    }

    private fun restoreCredential(authenticationResponseJson: String): RestoreCredential {
        val constructor = RestoreCredential::class.java.getDeclaredConstructor(
            String::class.java,
            Bundle::class.java,
        )
        constructor.isAccessible = true
        return constructor.newInstance(authenticationResponseJson, Bundle())
    }

    private companion object {
        const val VALID_REGISTRATION_RESPONSE_JSON = """{
          "id": "adnJdzQQOzHT8aobzfRCfA",
          "rawId": "adnJdzQQOzHT8aobzfRCfA",
          "response": {
            "clientDataJSON": "BAUG",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWpdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEGnZyXc0EDsx0_GqG830QnylAQIDJiABIVggd-XJL5odWHADN7Ayg5vk1LfCsAGqC9gpXHMtgtehFjoiWCAnkr58JQNicaTRIf7zALTm0G5Jh1BSTjlfi0HE05IyDA"
          }
        }"""

        const val VALID_AUTHENTICATION_RESPONSE_JSON = """{
          "id": "MzMzMzMzMzMzMzMzMzMzMw",
          "rawId": "MzMzMzMzMzMzMzMzMzMzMw",
          "response": {
            "clientDataJSON": "AQID",
            "authenticatorData": "REREREREREREREREREREREREREREREREREREREREREQFAAAAKg",
            "signature": "CQkJ"
          }
        }"""
    }
}
