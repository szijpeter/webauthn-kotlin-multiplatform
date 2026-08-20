package dev.webauthn.samples.composepasskey

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.toAuthenticationStartPayload
import dev.webauthn.samples.composepasskey.domain.passkey.toRegistrationStartPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class PasskeyDemoRequestsTest {
    @Test
    fun registration_normalizes_plaintext_handle_and_requires_resident_key() {
        val payload = config(userHandle = "demo-user").toRegistrationStartPayload()

        assertEquals(
            Base64UrlBytes.fromBytes("demo-user".encodeToByteArray()).encoded(),
            payload.userHandle,
        )
        assertEquals("required", payload.residentKey)
    }

    @Test
    fun registration_preserves_existing_base64url_handle() {
        val payload = config(userHandle = "AQID").toRegistrationStartPayload()

        assertEquals("AQID", payload.userHandle)
    }

    @Test
    fun blank_handle_uses_stable_demo_fallback() {
        val payload = config(userHandle = "  ").toRegistrationStartPayload()

        assertEquals(
            Base64UrlBytes.fromBytes("demo-user".encodeToByteArray()).encoded(),
            payload.userHandle,
        )
    }

    @Test
    fun authentication_is_discoverable_and_can_request_prf() {
        val salt = Base64UrlBytes.fromBytes(ByteArray(32) { 7 })
        val payload = config().toAuthenticationStartPayload(prfSalt = salt)

        assertEquals(null, payload.userName)
        assertEquals(salt.encoded(), payload.extensions?.prf?.eval?.first)
        assertNotNull(payload.extensions?.prf)
    }

    private fun config(userHandle: String = "demo-user-1"): PasskeyDemoConfig = PasskeyDemoConfig(
        endpointBase = "https://example.test",
        rpId = "example.test",
        origin = "https://example.test",
        userHandle = userHandle,
        userName = "demo@local",
    )
}
