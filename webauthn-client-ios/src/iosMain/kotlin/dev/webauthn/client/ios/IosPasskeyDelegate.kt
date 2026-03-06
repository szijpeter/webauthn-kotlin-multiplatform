package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyJsonMapper
import dev.webauthn.client.KotlinxPasskeyJsonMapper
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
    private val jsonMapper: PasskeyJsonMapper = KotlinxPasskeyJsonMapper(),
) : PasskeyPlatformBridge {
    private val json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    }

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse =
        jsonMapper.decodeRegistrationResponseOrThrowPlatform(
            bridge.createCredential(options).toRegistrationResponseJson(),
        )

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse =
        jsonMapper.decodeAuthenticationResponseOrThrowPlatform(
            bridge.getAssertion(options).toAuthenticationResponseJson(),
        )

    private fun IosRegistrationPayload.toRegistrationResponseJson(): String = json.encodeToString(
        RegistrationResponseDto.serializer(),
        RegistrationResponseDto(
            id = credentialId.toBase64Url(),
            rawId = rawId.toBase64Url(),
            response = RegistrationResponsePayloadDto(
                clientDataJson = clientDataJson.toBase64Url(),
                attestationObject = attestationObject.toBase64Url(),
            ),
            authenticatorAttachment = authenticatorAttachment,
        ),
    )

    private fun IosAuthenticationPayload.toAuthenticationResponseJson(): String = json.encodeToString(
        AuthenticationResponseDto.serializer(),
        AuthenticationResponseDto(
            id = credentialId.toBase64Url(),
            rawId = rawId.toBase64Url(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = clientDataJson.toBase64Url(),
                authenticatorData = authenticatorData.toBase64Url(),
                signature = signature.toBase64Url(),
                userHandle = userHandle?.toBase64Url(),
            ),
            authenticatorAttachment = authenticatorAttachment,
        ),
    )

    private fun ByteArray.toBase64Url(): String = Base64UrlBytes.fromBytes(this).encoded()

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
            supportsSecurityKey = major >= 15,
            platformVersionHints = listOf("iosMajor=$major"),
        )
    }
}
