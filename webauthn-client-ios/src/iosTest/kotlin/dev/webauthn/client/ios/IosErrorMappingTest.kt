package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClientError
import platform.AuthenticationServices.ASAuthorizationErrorCanceled
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.Foundation.NSError
import platform.Foundation.NSLocalizedDescriptionKey
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class IosErrorMappingTest {
    @Test
    fun testCancellationMapping() {
        val error = NSError(domain = ASAuthorizationErrorDomain, code = ASAuthorizationErrorCanceled, userInfo = null)
        val result = error.toPasskeyClientError()
        assertTrue(result is PasskeyClientError.UserCancelled)
    }

    @Test
    fun testOtherError() {
        val userInfo = mapOf<Any?, Any?>(NSLocalizedDescriptionKey to "Foo")
        val error = NSError(domain = "SomeDomain", code = 123, userInfo = userInfo)
        val result = error.toPasskeyClientError()
        assertTrue(result is PasskeyClientError.Platform)
        assertEquals("Foo", result.message)
    }
}
