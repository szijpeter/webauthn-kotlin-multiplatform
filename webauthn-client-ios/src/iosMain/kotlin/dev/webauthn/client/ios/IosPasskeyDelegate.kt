package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyJsonCodec
import dev.webauthn.client.KotlinxPasskeyJsonCodec
import dev.webauthn.client.decodeAuthenticationResponseOrThrowPlatform
import dev.webauthn.client.decodeRegistrationResponseOrThrowPlatform
import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.useContents
import kotlinx.serialization.json.Json
import platform.Foundation.NSProcessInfo
import platform.UIKit.UIApplication

internal actual class IosPasskeyDelegate(
    private val bridge: IosAuthorizationBridge,
) : PasskeyClient by DefaultPasskeyClient(
    bridge = IosPasskeyPlatformBridge(bridge),
) {
    actual constructor() : this(
        AuthenticationServicesAuthorizationBridge {
            checkNotNull(UIApplication.sharedApplication.keyWindow) { "No key window available" }
        },
    )
}

internal class IosPasskeyPlatformBridge(
    private val bridge: IosAuthorizationBridge,
    private val jsonCodec: PasskeyJsonCodec = KotlinxPasskeyJsonCodec(),
) : PasskeyPlatformBridge {
    private val json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    }

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
        val payload = bridge.createCredential(options)
        val responseJson = json.encodeToString(
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
        return jsonCodec.decodeRegistrationResponseOrThrowPlatform(responseJson)
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
        val payload = bridge.getAssertion(options)
        val responseJson = json.encodeToString(
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
        return jsonCodec.decodeAuthenticationResponseOrThrowPlatform(responseJson)
    }

    override fun mapPlatformError(throwable: Throwable): PasskeyClientError {
        return when (throwable) {
            is NSErrorException -> throwable.error.toPasskeyClientError()
            is IllegalArgumentException -> PasskeyClientError.InvalidOptions(throwable.message ?: "Invalid options")
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
}
