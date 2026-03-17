package dev.webauthn.client.ios

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IosAuthorizationBridgePolicyTest {
    @Test
    fun includesSecurityKeyRequest_whenPrfNotRequested_andRuntimeSupportsSecurityKey() {
        assertTrue(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = false,
                iosMajorVersion = 15,
            ),
        )
    }

    @Test
    fun excludesSecurityKeyRequest_whenPrfIsRequested() {
        assertFalse(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = true,
                iosMajorVersion = 18,
            ),
        )
    }

    @Test
    fun excludesSecurityKeyRequest_whenRuntimeIsTooOld() {
        assertFalse(
            shouldIncludeSecurityKeyAssertionRequest(
                prfRequested = false,
                iosMajorVersion = 14,
            ),
        )
    }
}
