package dev.webauthn.serialization

import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertTrue

class WebAuthnDtoMapperTest {
    @Test
    fun creationOptionsRejectInvalidRpId() {
        val dto = PublicKeyCredentialCreationOptionsDto(
            rp = RpEntityDto(id = "Example.COM", name = "Example"),
            user = UserEntityDto(
                id = "YWFhYWFhYWFhYWFhYWFhYQ",
                name = "alice",
                displayName = "Alice",
            ),
            challenge = "YWFhYWFhYWFhYWFhYWFhYQ",
            pubKeyCredParams = listOf(PublicKeyCredentialParametersDto(type = "public-key", alg = -7)),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid)
    }
}
