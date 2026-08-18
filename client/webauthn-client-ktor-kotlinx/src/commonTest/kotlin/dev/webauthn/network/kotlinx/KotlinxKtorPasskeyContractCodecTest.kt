package dev.webauthn.network.kotlinx

import dev.webauthn.client.CeremonyStart
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class KotlinxKtorPasskeyContractCodecTest {
    private val codec = KotlinxKtorPasskeyContractCodec()

    @Test
    fun registration_start_decodes_typed_options_with_unit_state() {
        val decoded = codec.decodeRegistrationStart(registrationOptionsJson())

        val started = assertIs<
            ValidationResult.Valid<CeremonyStart<Unit, PublicKeyCredentialCreationOptions>>,
        >(decoded).value
        assertEquals(Unit, started.state)
        assertEquals("example.com", started.options.rp.id.value)
        assertEquals("alice", started.options.user.name)
    }

    @Test
    fun authentication_start_decodes_typed_options_with_unit_state() {
        val decoded = codec.decodeAuthenticationStart(authenticationOptionsJson())

        val started = assertIs<
            ValidationResult.Valid<CeremonyStart<Unit, PublicKeyCredentialRequestOptions>>,
        >(decoded).value
        assertEquals(Unit, started.state)
        assertEquals("example.com", started.options.rpId?.value)
    }

    @Test
    fun finish_encoders_wrap_raw_responses_in_default_contract() {
        val registration = codec.encodeRegistrationFinish(Unit, rawRegistration())
        val authentication = codec.encodeAuthenticationFinish(Unit, rawAuthentication())

        assertContains(registration, "\"response\"")
        assertContains(registration, rawRegistration().credentialId.value.encoded())
        assertContains(authentication, "\"response\"")
        assertContains(authentication, rawAuthentication().signature.encoded())
    }

    @Test
    fun finish_decoders_map_verified_and_rejected_statuses() {
        assertEquals(
            DefaultPasskeyFinishResult.Verified,
            codec.decodeRegistrationFinish("""{"status":"ok"}"""),
        )
        assertIs<DefaultPasskeyFinishResult.Rejected>(
            codec.decodeAuthenticationFinish("""{"status":"rejected"}"""),
        )
    }

    @Test
    fun error_decoder_returns_only_structured_non_blank_messages() {
        assertEquals(
            "invalid challenge;origin rejected",
            codec.decodeError("""{"errors":["invalid challenge","","origin rejected"]}"""),
        )
        assertNull(codec.decodeError("not-json"))
    }
}

private fun registrationOptionsJson(): String = """
    {
      "rp":{"id":"example.com","name":"Example"},
      "user":{"id":"${UserHandle.fromBytes(byteArrayOf(1)).value.encoded()}","name":"alice","displayName":"Alice"},
      "challenge":"${Challenge.fromBytes(ByteArray(32) { 1 }).value.encoded()}",
      "pubKeyCredParams":[{"type":"public-key","alg":-7}]
    }
""".trimIndent()

private fun authenticationOptionsJson(): String = """
    {
      "challenge":"${Challenge.fromBytes(ByteArray(32) { 2 }).value.encoded()}",
      "rpId":"example.com"
    }
""".trimIndent()

private fun rawRegistration() = RawRegistrationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(1)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(2)),
    attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(3)),
)

private fun rawAuthentication() = RawAuthenticationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(4)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(5)),
    authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(6)),
    signature = Base64UrlBytes.fromBytes(byteArrayOf(7)),
)
