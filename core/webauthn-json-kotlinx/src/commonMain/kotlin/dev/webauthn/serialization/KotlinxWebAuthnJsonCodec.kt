package dev.webauthn.serialization

import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** kotlinx.serialization implementation of the neutral [WebAuthnJsonCodec] boundary. */
public class KotlinxWebAuthnJsonCodec(
    private val json: Json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    },
) : WebAuthnJsonCodec {
    override fun encodeCreationOptions(value: PublicKeyCredentialCreationOptions): String {
        return json.encodeToString(WebAuthnDtoMapper.fromModel(value))
    }

    override fun decodeCreationOptions(value: String): ValidationResult<PublicKeyCredentialCreationOptions> {
        return decode<PublicKeyCredentialCreationOptionsDto, PublicKeyCredentialCreationOptions>(
            value,
            WebAuthnDtoMapper::toModel,
        )
    }

    override fun encodeRequestOptions(value: PublicKeyCredentialRequestOptions): String {
        return json.encodeToString(WebAuthnDtoMapper.fromModel(value))
    }

    override fun decodeRequestOptions(value: String): ValidationResult<PublicKeyCredentialRequestOptions> {
        return decode<PublicKeyCredentialRequestOptionsDto, PublicKeyCredentialRequestOptions>(
            value,
            WebAuthnDtoMapper::toModel,
        )
    }

    override fun encodeRegistrationResponse(value: RawRegistrationResponse): String {
        return json.encodeToString(WebAuthnDtoMapper.fromModel(value))
    }

    override fun decodeRegistrationResponse(value: String): ValidationResult<RawRegistrationResponse> {
        return decode<RegistrationResponseDto, RawRegistrationResponse>(value, WebAuthnDtoMapper::toRawModel)
    }

    override fun encodeAuthenticationResponse(value: RawAuthenticationResponse): String {
        return json.encodeToString(WebAuthnDtoMapper.fromModel(value))
    }

    override fun decodeAuthenticationResponse(value: String): ValidationResult<RawAuthenticationResponse> {
        return decode<AuthenticationResponseDto, RawAuthenticationResponse>(value, WebAuthnDtoMapper::toRawModel)
    }

    override fun decodeCollectedClientData(value: Base64UrlBytes): ValidationResult<CollectedClientData> {
        return WebAuthnDtoMapper.parseCollectedClientData(value)
    }

    private inline fun <reified T, R> decode(
        value: String,
        crossinline mapper: (T) -> ValidationResult<R>,
    ): ValidationResult<R> {
        val dto = runCatching { json.decodeFromString<T>(value) }.getOrElse {
            return ValidationResult.Invalid(
                [
                    WebAuthnValidationError.InvalidFormat(
                        field = "json",
                        message = "WebAuthn JSON must match the expected response shape",
                    ),
                ],
            )
        }
        return mapper(dto)
    }
}
