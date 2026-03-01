package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.SharedPasskeyClient
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.useContents
import kotlinx.serialization.json.Json
import platform.Foundation.NSProcessInfo
import platform.UIKit.UIApplication

internal actual class IosPasskeyDelegate(
    private val bridge: IosAuthorizationBridge,
) : PasskeyClient by SharedPasskeyClient(
    bridge = IosPasskeyPlatformBridge(bridge),
    jsonCodec = IosKotlinxPasskeyJsonCodec(),
) {
    actual constructor() : this(
        AuthenticationServicesAuthorizationBridge {
            checkNotNull(UIApplication.sharedApplication.keyWindow) { "No key window available" }
        },
    )
}

internal class IosPasskeyPlatformBridge(
    private val bridge: IosAuthorizationBridge,
) : PasskeyPlatformBridge {
    private val json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    }

    override suspend fun createCredential(requestJson: String): String {
        val options = parseCreationOptions(requestJson)
        val payload = bridge.createCredential(options)
        return json.encodeToString(
            RegistrationResponseDto.serializer(),
            RegistrationResponseDto(
                id = Base64UrlBytes.fromBytes(payload.credentialId).encoded(),
                rawId = Base64UrlBytes.fromBytes(payload.rawId).encoded(),
                response = RegistrationResponsePayloadDto(
                    clientDataJson = Base64UrlBytes.fromBytes(payload.clientDataJson).encoded(),
                    attestationObject = Base64UrlBytes.fromBytes(payload.attestationObject).encoded(),
                ),
                authenticatorAttachment = payload.authenticatorAttachment,
            ),
        )
    }

    override suspend fun getAssertion(requestJson: String): String {
        val options = parseAssertionOptions(requestJson)
        val payload = bridge.getAssertion(options)
        return json.encodeToString(
            AuthenticationResponseDto.serializer(),
            AuthenticationResponseDto(
                id = Base64UrlBytes.fromBytes(payload.credentialId).encoded(),
                rawId = Base64UrlBytes.fromBytes(payload.rawId).encoded(),
                response = AuthenticationResponsePayloadDto(
                    clientDataJson = Base64UrlBytes.fromBytes(payload.clientDataJson).encoded(),
                    authenticatorData = Base64UrlBytes.fromBytes(payload.authenticatorData).encoded(),
                    signature = Base64UrlBytes.fromBytes(payload.signature).encoded(),
                    userHandle = payload.userHandle?.let { Base64UrlBytes.fromBytes(it).encoded() },
                ),
                authenticatorAttachment = payload.authenticatorAttachment,
            ),
        )
    }

    override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
        return when (throwable) {
            is NSErrorException -> throwable.error.toPasskeyClientError()
            else -> PasskeyClientError.Platform(throwable.message ?: "Unknown platform error", throwable)
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    override suspend fun capabilities(): PasskeyCapabilities {
        val version = NSProcessInfo.processInfo.operatingSystemVersion
        val major = version.useContents { majorVersion.toInt() }
        return PasskeyCapabilities(
            supportsPrf = major >= 18,
            supportsLargeBlobRead = major >= 17,
            supportsLargeBlobWrite = major >= 17,
            supportsSecurityKey = true,
            platformVersionHints = listOf("iosMajor=$major"),
        )
    }

    private fun parseCreationOptions(payload: String): PublicKeyCredentialCreationOptions {
        val dto = json.decodeFromString(PublicKeyCredentialCreationOptionsDto.serializer(), payload)
        return when (val parsed = WebAuthnDtoMapper.toModel(dto)) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                val firstError = parsed.errors.first()
                throw IllegalArgumentException("${firstError.field}: ${firstError.message}")
            }
        }
    }

    private fun parseAssertionOptions(payload: String): PublicKeyCredentialRequestOptions {
        val dto = json.decodeFromString(PublicKeyCredentialRequestOptionsDto.serializer(), payload)
        return when (val parsed = WebAuthnDtoMapper.toModel(dto)) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                val firstError = parsed.errors.first()
                throw IllegalArgumentException("${firstError.field}: ${firstError.message}")
            }
        }
    }
}
