package dev.webauthn.client.defaults

import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import kotlin.test.Test
import kotlin.test.assertIs

class DefaultPasskeyClientConfigurationTest {

    @Test
    fun uses_kotlinx_codec_by_default() {
        assertIs<KotlinxWebAuthnJsonCodec>(DefaultPasskeyClientConfiguration().codec)
    }
}
