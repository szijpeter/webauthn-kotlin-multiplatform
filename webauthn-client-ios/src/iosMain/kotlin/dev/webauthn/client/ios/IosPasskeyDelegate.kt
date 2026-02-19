package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ValidationResult
import platform.UIKit.UIApplication

internal actual class IosPasskeyDelegate(
    private val bridge: IosAuthorizationBridge = AuthenticationServicesAuthorizationBridge {
        UIApplication.sharedApplication.keyWindow ?: throw IllegalStateException("No key window available")
    }
) {
    actual constructor() : this(AuthenticationServicesAuthorizationBridge {
        UIApplication.sharedApplication.keyWindow ?: throw IllegalStateException("No key window available")
    })
    actual suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return try {
            val payload = bridge.createCredential(options)
            val dto = RegistrationResponseDto(
                id = Base64UrlBytes.fromBytes(payload.credentialId).encoded(),
                rawId = Base64UrlBytes.fromBytes(payload.rawId).encoded(),
                response = RegistrationResponsePayloadDto(
                    clientDataJson = Base64UrlBytes.fromBytes(payload.clientDataJson).encoded(),
                    attestationObject = Base64UrlBytes.fromBytes(payload.attestationObject).encoded(),
                )
            )
            when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
                is ValidationResult.Valid -> PasskeyResult.Success(modelResult.value)
                is ValidationResult.Invalid -> {
                    val firstError = modelResult.errors.first()
                    PasskeyResult.Failure(PasskeyClientError.Platform("${firstError.field}: ${firstError.message}"))
                }
            }
        } catch (e: NSErrorException) {
            PasskeyResult.Failure(e.error.toPasskeyClientError())
        } catch (e: Exception) {
            PasskeyResult.Failure(PasskeyClientError.Platform(e.message ?: "Unknown platform error", e))
        }
    }

    actual suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return try {
            val payload = bridge.getAssertion(options)
            val dto = AuthenticationResponseDto(
                id = Base64UrlBytes.fromBytes(payload.credentialId).encoded(),
                rawId = Base64UrlBytes.fromBytes(payload.rawId).encoded(),
                response = AuthenticationResponsePayloadDto(
                    clientDataJson = Base64UrlBytes.fromBytes(payload.clientDataJson).encoded(),
                    authenticatorData = Base64UrlBytes.fromBytes(payload.authenticatorData).encoded(),
                    signature = Base64UrlBytes.fromBytes(payload.signature).encoded(),
                    userHandle = payload.userHandle?.let { Base64UrlBytes.fromBytes(it).encoded() }
                )
            )
            when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
                is ValidationResult.Valid -> PasskeyResult.Success(modelResult.value)
                is ValidationResult.Invalid -> {
                    val firstError = modelResult.errors.first()
                    PasskeyResult.Failure(PasskeyClientError.Platform("${firstError.field}: ${firstError.message}"))
                }
            }
        } catch (e: NSErrorException) {
            PasskeyResult.Failure(e.error.toPasskeyClientError())
        } catch (e: Exception) {
            PasskeyResult.Failure(PasskeyClientError.Platform(e.message ?: "Unknown platform error", e))
        }
    }
}
