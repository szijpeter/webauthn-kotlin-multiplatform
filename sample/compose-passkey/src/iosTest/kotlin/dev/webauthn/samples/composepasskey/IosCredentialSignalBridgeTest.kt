package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.samples.composepasskey.domain.signals.IosBridgeCredentialSignalDemoClient
import dev.webauthn.samples.composepasskey.domain.signals.IosCredentialSignalBridge
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IosCredentialSignalBridgeTest {
    @Test
    fun signalCurrentUserDetails_forwards_values_toSwiftBridge() = runBlocking {
        val bridge = FakeIosCredentialSignalBridge()
        val client = IosBridgeCredentialSignalDemoClient(bridge)

        val result = client.signalCurrentUserDetails(
            rpId = RpId.parseOrThrow("example.com"),
            userId = UserHandle.fromBytes("demo-user".encodeToByteArray()),
            name = "demo",
            displayName = "Demo User",
        )

        assertTrue(result is PasskeyResult.Success)
        assertEquals("example.com", bridge.lastRelyingPartyIdentifier)
        assertEquals("ZGVtby11c2Vy", bridge.lastUserHandleBase64Url)
        assertEquals("demo", bridge.lastName)
        assertEquals("Demo User", bridge.lastDisplayName)
    }

    @Test
    fun signalCurrentUserDetails_returnsFailure_whenBridgeIsUnavailable() = runBlocking {
        val client = IosBridgeCredentialSignalDemoClient(
            FakeIosCredentialSignalBridge(isAvailable = false),
        )

        val result = client.signalCurrentUserDetails(
            rpId = RpId.parseOrThrow("example.com"),
            userId = UserHandle.fromBytes("demo-user".encodeToByteArray()),
            name = "demo",
            displayName = "Demo User",
        )

        assertTrue(result is PasskeyResult.Failure)
        assertTrue(result.error.message.contains("iOS 26.2+"))
    }

    @Test
    fun signalCurrentUserDetails_returnsFailure_whenBridgeReportsError() = runBlocking {
        val client = IosBridgeCredentialSignalDemoClient(
            FakeIosCredentialSignalBridge(errorMessage = "ASCredentialDataManager failed"),
        )

        val result = client.signalCurrentUserDetails(
            rpId = RpId.parseOrThrow("example.com"),
            userId = UserHandle.fromBytes("demo-user".encodeToByteArray()),
            name = "demo",
            displayName = "Demo User",
        )

        assertTrue(result is PasskeyResult.Failure)
        assertEquals("ASCredentialDataManager failed", result.error.message)
    }

    private class FakeIosCredentialSignalBridge(
        override val isAvailable: Boolean = true,
        private val errorMessage: String? = null,
    ) : IosCredentialSignalBridge {
        var lastRelyingPartyIdentifier: String? = null
        var lastUserHandleBase64Url: String? = null
        var lastName: String? = null
        var lastDisplayName: String? = null

        override fun reportCurrentUserDetails(
            relyingPartyIdentifier: String,
            userHandleBase64Url: String,
            name: String,
            displayName: String,
            completion: (String?) -> Unit,
        ) {
            lastRelyingPartyIdentifier = relyingPartyIdentifier
            lastUserHandleBase64Url = userHandleBase64Url
            lastName = name
            lastDisplayName = displayName
            completion(errorMessage)
        }
    }
}
