package dev.webauthn.client.ios

import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyJsonMapper
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.decodeAuthenticationResponseOrThrowPlatform
import dev.webauthn.client.decodeRegistrationResponseOrThrowPlatform
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.useContents
import kotlinx.serialization.json.Json
import platform.Foundation.NSProcessInfo

internal actual class IosPasskeyClientImpl(
    private val bridge: IosAuthorizationBridge,
) : PasskeyClient by DefaultPasskeyClient(
    bridge = IosPasskeyPlatformBridge(bridge),
) {
    actual constructor() : this(
        AuthenticationServicesAuthorizationBridge(UIKitPasskeyPresentationAnchorProvider),
    )

    internal constructor(
        anchorProvider: PasskeyPresentationAnchorProvider,
    ) : this(
        AuthenticationServicesAuthorizationBridge(anchorProvider),
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

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
        return bridge
            .createCredential(options)
            .toModel()
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
        return bridge
            .getAssertion(options)
            .toModel()
    }

    private fun IosRegistrationPayload.toModel(): RegistrationResponse {
        return jsonMapper.decodeRegistrationResponseOrThrowPlatform(asRegistrationResponseJson())
    }

    private fun IosAuthenticationPayload.toModel(): AuthenticationResponse {
        return jsonMapper.decodeAuthenticationResponseOrThrowPlatform(asAuthenticationResponseJson())
    }

    private fun IosRegistrationPayload.asRegistrationResponseJson(): String = json.encodeToString(
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

    private fun IosAuthenticationPayload.asAuthenticationResponseJson(): String = json.encodeToString(
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
            clientExtensionResults = extensions?.let(WebAuthnDtoMapper::fromModel),
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
    @Suppress("MagicNumber")
    override suspend fun capabilities(): PasskeyCapabilities {
        val version = NSProcessInfo.processInfo.operatingSystemVersion
        val major = version.useContents { majorVersion.toInt() }
        return PasskeyCapabilities(
            supported = buildSet {
                if (major >= 18) add(PasskeyCapability.Extension(WebAuthnExtension.Prf))
                if (major >= 17) add(PasskeyCapability.Extension(WebAuthnExtension.LargeBlob))
                if (major >= 15) add(PasskeyCapability.PlatformFeature("securityKey"))
            },
            platformVersionHints = listOf("iosMajor=$major"),
        )
    }
}
