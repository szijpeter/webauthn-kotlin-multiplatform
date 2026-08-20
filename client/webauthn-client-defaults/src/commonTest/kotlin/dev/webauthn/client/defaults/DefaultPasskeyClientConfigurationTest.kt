package dev.webauthn.client.defaults

import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.model.Base64UrlBytes
import kotlin.test.Test
import kotlin.test.assertNotNull

class DefaultPasskeyClientConfigurationTest {
    @Test
    fun default_configuration_has_a_codec_and_allows_override() {
        val configuration = DefaultPasskeyClientConfiguration()
        assertNotNull(configuration.codec)
        val replacement = object : WebAuthnJsonCodec {
            override fun encodeRegistrationResponse(value: dev.webauthn.model.RawRegistrationResponse) = "{}"
            override fun decodeRegistrationResponse(value: String) = error("unused")
            override fun encodeAuthenticationResponse(value: dev.webauthn.model.RawAuthenticationResponse) = "{}"
            override fun decodeAuthenticationResponse(value: String) = error("unused")
            override fun decodeCollectedClientData(value: Base64UrlBytes) = error("unused")
            override fun encodeCreationOptions(value: dev.webauthn.model.PublicKeyCredentialCreationOptions) = "{}"
            override fun decodeCreationOptions(value: String) = error("unused")
            override fun encodeRequestOptions(value: dev.webauthn.model.PublicKeyCredentialRequestOptions) = "{}"
            override fun decodeRequestOptions(value: String) = error("unused")
        }
        configuration.codec = replacement
        assertNotNull(configuration.codec)
    }
}
