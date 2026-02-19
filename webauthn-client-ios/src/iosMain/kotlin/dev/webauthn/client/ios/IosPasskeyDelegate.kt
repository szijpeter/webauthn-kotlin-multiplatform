package dev.webauthn.client.ios

import at.asitplus.KmmResult
import at.asitplus.catching
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import platform.UIKit.UIApplication

internal actual class IosPasskeyDelegate(
    private val bridge: IosAuthorizationBridge = AuthenticationServicesAuthorizationBridge {
        checkNotNull(UIApplication.sharedApplication.keyWindow) { "No key window available" }
    }
) {
    actual constructor() : this(AuthenticationServicesAuthorizationBridge {
        checkNotNull(UIApplication.sharedApplication.keyWindow) { "No key window available" }
    })

    actual suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return catching { bridge.createCredential(options) }
            .transform(::toRegistrationDto)
            .transform(::toRegistrationModel)
            .toPasskeyResult()
    }

    actual suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return catching { bridge.getAssertion(options) }
            .transform(::toAuthenticationDto)
            .transform(::toAuthenticationModel)
            .toPasskeyResult()
    }

    private fun <T> KmmResult<T>.toPasskeyResult(): PasskeyResult<T> = fold(
        onSuccess = { PasskeyResult.Success(it) },
        onFailure = { error ->
            when (error) {
                is NSErrorException -> PasskeyResult.Failure(error.error.toPasskeyClientError())
                else -> PasskeyResult.Failure(PasskeyClientError.Platform(error.message ?: "Unknown platform error", error))
            }
        }
    )

    private fun toRegistrationDto(payload: IosRegistrationPayload): KmmResult<RegistrationResponseDto> = catching {
        RegistrationResponseDto(
            id = Base64UrlBytes.fromBytes(payload.credentialId).encoded(),
            rawId = Base64UrlBytes.fromBytes(payload.rawId).encoded(),
            response = RegistrationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(payload.clientDataJson).encoded(),
                attestationObject = Base64UrlBytes.fromBytes(payload.attestationObject).encoded(),
            ),
        )
    }

    private fun toAuthenticationDto(payload: IosAuthenticationPayload): KmmResult<AuthenticationResponseDto> = catching {
        AuthenticationResponseDto(
            id = Base64UrlBytes.fromBytes(payload.credentialId).encoded(),
            rawId = Base64UrlBytes.fromBytes(payload.rawId).encoded(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(payload.clientDataJson).encoded(),
                authenticatorData = Base64UrlBytes.fromBytes(payload.authenticatorData).encoded(),
                signature = Base64UrlBytes.fromBytes(payload.signature).encoded(),
                userHandle = payload.userHandle?.let { Base64UrlBytes.fromBytes(it).encoded() },
            ),
        )
    }

    private fun toRegistrationModel(dto: RegistrationResponseDto): KmmResult<RegistrationResponse> =
        when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
            is ValidationResult.Valid -> KmmResult(modelResult.value)
            is ValidationResult.Invalid -> {
                val firstError = modelResult.errors.first()
                failureResult("${firstError.field}: ${firstError.message}")
            }
        }

    private fun toAuthenticationModel(dto: AuthenticationResponseDto): KmmResult<AuthenticationResponse> =
        when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
            is ValidationResult.Valid -> KmmResult(modelResult.value)
            is ValidationResult.Invalid -> {
                val firstError = modelResult.errors.first()
                failureResult("${firstError.field}: ${firstError.message}")
            }
        }

    private fun <T> failureResult(message: String): KmmResult<T> =
        KmmResult(IllegalArgumentException(message))
}
