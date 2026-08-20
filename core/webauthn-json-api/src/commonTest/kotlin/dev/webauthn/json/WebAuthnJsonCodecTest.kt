package dev.webauthn.json

import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import kotlin.test.Test

class WebAuthnJsonCodecTest {
    @Test
    fun thirdPartyCodecCanImplementTheWebAuthnSpecificBoundary() {
        val codec: WebAuthnJsonCodec = object : WebAuthnJsonCodec {
            override fun encodeCreationOptions(value: PublicKeyCredentialCreationOptions): String = "{}"
            override fun decodeCreationOptions(value: String): ValidationResult<PublicKeyCredentialCreationOptions> = error("unused")
            override fun encodeRequestOptions(value: PublicKeyCredentialRequestOptions): String = "{}"
            override fun decodeRequestOptions(value: String): ValidationResult<PublicKeyCredentialRequestOptions> = error("unused")
            override fun encodeRegistrationResponse(value: RawRegistrationResponse): String = "{}"
            override fun decodeRegistrationResponse(value: String): ValidationResult<RawRegistrationResponse> = error("unused")
            override fun encodeAuthenticationResponse(value: RawAuthenticationResponse): String = "{}"
            override fun decodeAuthenticationResponse(value: String): ValidationResult<RawAuthenticationResponse> = error("unused")
            override fun decodeCollectedClientData(value: Base64UrlBytes): ValidationResult<CollectedClientData> =
                error("unused")
        }

    }
}
