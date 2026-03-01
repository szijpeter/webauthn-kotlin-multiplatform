package dev.webauthn.client.android

import dev.webauthn.client.PasskeyJsonCodec
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal class AndroidKotlinxPasskeyJsonCodec(
    private val requestJson: Json = Json { encodeDefaults = false },
    private val responseJson: Json = Json { ignoreUnknownKeys = true },
) : PasskeyJsonCodec {
    override fun encodeCreationOptions(options: PublicKeyCredentialCreationOptions): String {
        return requestJson.encodeToString(
            PublicKeyCredentialCreationOptionsDto.serializer(),
            WebAuthnDtoMapper.fromModel(options),
        )
    }

    override fun decodeCreationOptions(payload: String): ValidationResult<PublicKeyCredentialCreationOptions> {
        val dto = requestJson.decodeFromString(PublicKeyCredentialCreationOptionsDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }

    override fun encodeAssertionOptions(options: PublicKeyCredentialRequestOptions): String {
        return requestJson.encodeToString(
            PublicKeyCredentialRequestOptionsDto.serializer(),
            WebAuthnDtoMapper.fromModel(options),
        )
    }

    override fun decodeAssertionOptions(payload: String): ValidationResult<PublicKeyCredentialRequestOptions> {
        val dto = requestJson.decodeFromString(PublicKeyCredentialRequestOptionsDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }

    override fun encodeRegistrationResponse(response: RegistrationResponse): String {
        return responseJson.encodeToString(
            RegistrationResponseDto.serializer(),
            WebAuthnDtoMapper.fromModel(response),
        )
    }

    override fun decodeRegistrationResponse(payload: String): ValidationResult<RegistrationResponse> {
        val dto = responseJson.decodeFromString(RegistrationResponseDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }

    override fun encodeAuthenticationResponse(response: AuthenticationResponse): String {
        return responseJson.encodeToString(
            AuthenticationResponseDto.serializer(),
            WebAuthnDtoMapper.fromModel(response),
        )
    }

    override fun decodeAuthenticationResponse(payload: String): ValidationResult<AuthenticationResponse> {
        val dto = responseJson.decodeFromString(AuthenticationResponseDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }
}
