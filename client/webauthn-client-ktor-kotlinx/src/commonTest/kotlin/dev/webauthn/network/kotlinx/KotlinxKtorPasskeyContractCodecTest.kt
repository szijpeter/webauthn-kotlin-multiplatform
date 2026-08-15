package dev.webauthn.network.kotlinx

import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class KotlinxKtorPasskeyContractCodecTest {
    private val codec = KotlinxKtorPasskeyContractCodec()

    @Test
    fun registrationStart_decodes_typed_options() {
        val result = codec.decodeRegistrationStart(
            """{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"example.com","name":"Example"},"user":{"id":"AQID","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}""",
        )

        val valid = assertIs<ValidationResult.Valid<PublicKeyCredentialCreationOptions>>(result)
        assertEquals("example.com", valid.value.rp.id.value)
    }

    @Test
    fun registrationFinish_encodes_raw_response_without_trusted_client_data_fields() {
        val encoded = codec.encodeRegistrationFinish(
            RawRegistrationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(1, 2, 3)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
                attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(7, 8, 9)),
            ),
        )

        assertTrue(encoded.contains("clientDataJSON"))
        assertTrue(!encoded.contains("challenge"))
        assertTrue(!encoded.contains("origin"))
    }

    @Test
    fun finish_and_error_results_are_decoded_deterministically() {
        assertEquals(PasskeyFinishResult.Verified, codec.decodeRegistrationFinish("""{"status":"ok"}"""))
        assertEquals("first; second", codec.decodeError("""{"errors":["first","second"]}"""))
    }
}
