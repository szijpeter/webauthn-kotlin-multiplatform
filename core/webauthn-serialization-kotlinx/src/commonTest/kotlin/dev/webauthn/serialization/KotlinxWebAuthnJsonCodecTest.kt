package dev.webauthn.serialization

import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KotlinxWebAuthnJsonCodecTest {
    private val codec = KotlinxWebAuthnJsonCodec()

    @Test
    fun decodesRegistrationResponseWithoutParsingAuthenticatorData() {
        val result = codec.decodeRegistrationResponse(
            """{"id":"Y3JlZGVudGlhbA","rawId":"Y3JlZGVudGlhbA","response":{"clientDataJSON":"e30","attestationObject":"AA"},"type":"public-key"}""",
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals("Y3JlZGVudGlhbA", result.value.credentialId.value.encoded())
    }
}
