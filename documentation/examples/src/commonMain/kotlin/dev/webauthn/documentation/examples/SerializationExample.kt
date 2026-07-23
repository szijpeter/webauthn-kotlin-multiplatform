package dev.webauthn.documentation.examples

// docs-region serialization-mapper
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.WebAuthnDtoMapper

fun decodeRequestOptions(
    dto: PublicKeyCredentialRequestOptionsDto,
): ValidationResult<PublicKeyCredentialRequestOptions> {
    return WebAuthnDtoMapper.toModel(dto)
}

fun encodeRequestOptions(
    model: PublicKeyCredentialRequestOptions,
): PublicKeyCredentialRequestOptionsDto {
    return WebAuthnDtoMapper.fromModel(model)
}
// docs-endregion serialization-mapper
