package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.SignalAllAcceptedCredentialIdsRequest
import androidx.credentials.SignalCredentialStateRequest
import androidx.credentials.SignalCredentialStateResponse
import androidx.credentials.SignalCurrentUserDetailsRequest
import androidx.credentials.SignalUnknownCredentialRequest
import androidx.credentials.exceptions.publickeycredential.SignalCredentialUnknownException
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import io.mockk.CapturingSlot
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidCredentialSignalClientTest {
    @Test
    fun signalAllAcceptedCredentialIds_forwards_expected_request_json() = runBlocking {
        val request = slot<SignalCredentialStateRequest>()
        val credentialManager = recordingCredentialManager(request)
        val client = AndroidCredentialSignalClient(
            context = mockk(relaxed = true),
            credentialManagerFactory = { credentialManager },
        )

        val result = client.signalAllAcceptedCredentialIds(
            rpId = RpId.parseOrThrow("example.com"),
            userId = UserHandle.fromBytes(byteArrayOf(1, 2, 3)),
            credentialIds = listOf(
                CredentialId.fromBytes(byteArrayOf(4, 5, 6)),
                CredentialId.fromBytes(byteArrayOf(7, 8, 9)),
            ),
        )

        assertTrue(result is PasskeyResult.Success)
        assertTrue(request.captured is SignalAllAcceptedCredentialIdsRequest)
        val json = JSONObject(request.captured.requestJson)
        assertEquals("example.com", json.getString("rpId"))
        assertEquals("AQID", json.getString("userId"))
        val acceptedIds = json.getJSONArray("allAcceptedCredentialIds")
        assertEquals("BAUG", acceptedIds.getString(0))
        assertEquals("BwgJ", acceptedIds.getString(1))
    }

    @Test
    fun signalUnknownCredential_forwards_expected_request_json() = runBlocking {
        val request = slot<SignalCredentialStateRequest>()
        val credentialManager = recordingCredentialManager(request)
        val client = AndroidCredentialSignalClient(
            context = mockk(relaxed = true),
            credentialManagerFactory = { credentialManager },
        )

        val result = client.signalUnknownCredential(
            rpId = RpId.parseOrThrow("example.com"),
            credentialId = CredentialId.fromBytes(byteArrayOf(4, 5, 6)),
        )

        assertTrue(result is PasskeyResult.Success)
        assertTrue(request.captured is SignalUnknownCredentialRequest)
        val json = JSONObject(request.captured.requestJson)
        assertEquals("example.com", json.getString("rpId"))
        assertEquals("BAUG", json.getString("credentialId"))
    }

    @Test
    fun signalCurrentUserDetails_forwards_expected_request_json() = runBlocking {
        val request = slot<SignalCredentialStateRequest>()
        val credentialManager = recordingCredentialManager(request)
        val client = AndroidCredentialSignalClient(
            context = mockk(relaxed = true),
            credentialManagerFactory = { credentialManager },
        )

        val result = client.signalCurrentUserDetails(
            rpId = RpId.parseOrThrow("example.com"),
            userId = UserHandle.fromBytes(byteArrayOf(1, 2, 3)),
            name = "demo@example.com",
            displayName = "Demo User",
        )

        assertTrue(result is PasskeyResult.Success)
        assertTrue(request.captured is SignalCurrentUserDetailsRequest)
        val json = JSONObject(request.captured.requestJson)
        assertEquals("example.com", json.getString("rpId"))
        assertEquals("AQID", json.getString("userId"))
        assertEquals("demo@example.com", json.getString("name"))
        assertEquals("Demo User", json.getString("displayName"))
    }

    @Test
    fun signalUnknownCredential_maps_provider_error_to_platform_failure() = runBlocking {
        val credentialManager = mockk<CredentialManager>(relaxed = true)
        val client = AndroidCredentialSignalClient(
            context = mockk(relaxed = true),
            credentialManagerFactory = { credentialManager },
        )
        coEvery {
            credentialManager.signalCredentialState(any())
        } throws SignalCredentialUnknownException("provider unavailable")

        val result = client.signalUnknownCredential(
            rpId = RpId.parseOrThrow("example.com"),
            credentialId = CredentialId.fromBytes(byteArrayOf(4, 5, 6)),
        )

        assertTrue(result is PasskeyResult.Failure)
        val failure = result as PasskeyResult.Failure
        assertTrue(failure.error is PasskeyClientError.Platform)
        assertTrue(failure.error.message.contains("provider unavailable"))
    }

    private fun recordingCredentialManager(
        request: CapturingSlot<SignalCredentialStateRequest>,
    ): CredentialManager {
        val credentialManager = mockk<CredentialManager>(relaxed = true)
        coEvery {
            credentialManager.signalCredentialState(capture(request))
        } returns SignalCredentialStateResponse()
        return credentialManager
    }
}
