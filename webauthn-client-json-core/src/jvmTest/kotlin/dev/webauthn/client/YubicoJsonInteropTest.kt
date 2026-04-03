package dev.webauthn.client

import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.data.ByteArray as YubicoByteArray
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.PublicKeyCredentialType
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class YubicoJsonInteropTest {
    private val mapper = KotlinxPasskeyJsonMapper()

    @Test
    fun decodeCreationOptions_acceptsYubicoCredentialsCreateJson() {
        val yubicoJson = PublicKeyCredentialCreationOptions.builder()
            .rp(
                RelyingPartyIdentity.builder()
                    .id("example.com")
                    .name("Example")
                    .build(),
            )
            .user(
                UserIdentity.builder()
                    .name("alice")
                    .displayName("Alice")
                    .id(YubicoByteArray.fromBase64Url("AQID"))
                    .build(),
            )
            .challenge(YubicoByteArray.fromBase64Url("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            .pubKeyCredParams(listOf(PublicKeyCredentialParameters.ES256))
            .build()
            .toJson()

        val decoded = mapper.decodeCreationOptionsOrThrowInvalid(yubicoJson)

        assertEquals("example.com", decoded.rp.id.value)
        assertEquals("alice", decoded.user.name)
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", decoded.challenge.value.encoded())
        assertEquals(-7, decoded.pubKeyCredParams.single().alg)
    }

    @Test
    fun decodeAssertionOptions_acceptsYubicoCredentialsGetJson() {
        val yubicoJson = PublicKeyCredentialRequestOptions.builder()
            .challenge(YubicoByteArray.fromBase64Url("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"))
            .rpId("example.com")
            .allowCredentials(
                listOf(
                    PublicKeyCredentialDescriptor.builder()
                        .id(YubicoByteArray.fromBase64Url("MzMzMzMzMzMzMzMzMzMzMw"))
                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                        .build(),
                ),
            )
            .build()
            .toCredentialsGetJson()
        val publicKeyPayload = Json.parseToJsonElement(yubicoJson).jsonObject["publicKey"]!!.toString()

        val decoded = mapper.decodeAssertionOptionsOrThrowInvalid(publicKeyPayload)

        assertEquals("example.com", decoded.rpId?.value)
        assertEquals("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", decoded.challenge.value.encoded())
        assertEquals("MzMzMzMzMzMzMzMzMzMzMw", decoded.allowCredentials.single().id.value.encoded())
    }

    @Test
    fun encodeRegistrationResponse_producesJsonYubicoCanParse() {
        val response = mapper.decodeRegistrationResponseOrThrowPlatform(
            """
            {
              "id": "adnJdzQQOzHT8aobzfRCfA",
              "rawId": "adnJdzQQOzHT8aobzfRCfA",
              "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiT2NhNkJqajNRRFBybmNhTUJ0VURxXzZnSk5VSmw2bXZxLVZjNW4wNXl3MCIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOnJZbjV5Tk5MR1dFb2h0NW5uVXc0akVCRmJubkE5YmNCRmt2bzBRdnBsM2cifQ",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWpdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEGnZyXc0EDsx0_GqG830QnylAQIDJiABIVggd-XJL5odWHADN7Ayg5vk1LfCsAGqC9gpXHMtgtehFjoiWCAnkr58JQNicaTRIf7zALTm0G5Jh1BSTjlfi0HE05IyDA"
              },
              "type": "public-key",
              "clientExtensionResults": {}
            }
            """.trimIndent(),
        )

        val encoded = mapper.encodeRegistrationResponse(response)
        val yubicoParsed = PublicKeyCredential.parseRegistrationResponseJson(encoded)

        assertEquals(response.credentialId.value.encoded(), yubicoParsed.id.base64Url)
        assertEquals(response.attestationObject.encoded(), yubicoParsed.response.attestationObject.base64Url)
    }

    @Test
    fun encodeAuthenticationResponse_producesJsonYubicoCanParse() {
        val response = mapper.decodeAuthenticationResponseOrThrowPlatform(
            """
            {
              "id": "adnJdzQQOzHT8aobzfRCfA",
              "rawId": "adnJdzQQOzHT8aobzfRCfA",
              "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSnBFMlhkeG1yTnFwZTFsb1lFY2ZtOEtfb1pmQWtFMVpTd0VJdU1FT0JPQSIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOlZiai1tUGU5eDBORWlIREdHM0VPaTA0RVRHVDVTSW9FYzNmMnpwYzdxQzgiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJkZXYud2ViYXV0aG4uc2FtcGxlcy5jb21wb3NlcGFzc2tleS5hbmRyb2lkIn0",
                "authenticatorData": "1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWodAAAAAA",
                "signature": "MEYCIQDK_YzkGEhtIf4K6XM8LAjU4f3qASY3J5cgggiQOW7Y6wIhAKqCT7k80zLi_GADyhg41TK6S32uaSJiZ_aGzM_gfiCk",
                "userHandle": "NDI"
              },
              "type": "public-key",
              "clientExtensionResults": {}
            }
            """.trimIndent(),
        )

        val encoded = mapper.encodeAuthenticationResponse(response)
        val yubicoParsed = PublicKeyCredential.parseAssertionResponseJson(encoded)

        assertEquals(response.credentialId.value.encoded(), yubicoParsed.id.base64Url)
        assertEquals(response.signature.encoded(), yubicoParsed.response.signature.base64Url)
        assertEquals(response.rawAuthenticatorData.encoded(), yubicoParsed.response.authenticatorData.base64Url)
        assertTrue(yubicoParsed.response.userHandle.isPresent)
    }
}
