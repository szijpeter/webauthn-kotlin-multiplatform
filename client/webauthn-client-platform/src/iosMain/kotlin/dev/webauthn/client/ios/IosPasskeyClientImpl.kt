package dev.webauthn.client.ios

import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.WebAuthnExtension
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.useContents
import platform.Foundation.NSProcessInfo

internal class IosPasskeyClientImpl(
    private val bridge: IosAuthorizationBridge,
) : PasskeyClient by DefaultPasskeyClient(
    bridge = IosPasskeyPlatformBridge(bridge),
) {
    constructor() : this(
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
) : PasskeyPlatformBridge {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RawRegistrationResponse {
        return bridge
            .createCredential(options)
            .toRaw()
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): RawAuthenticationResponse {
        return bridge
            .getAssertion(options)
            .toRaw()
    }

    private fun IosRegistrationPayload.toRaw(): RawRegistrationResponse {
        requireMatchingCredentialIds(credentialId, rawId)
        return RawRegistrationResponse(
            credentialId = CredentialId.fromBytes(rawId),
            clientDataJson = Base64UrlBytes.fromBytes(clientDataJson),
            attestationObject = Base64UrlBytes.fromBytes(attestationObject),
            authenticatorAttachment = authenticatorAttachment.toModel(),
        )
    }

    private fun IosAuthenticationPayload.toRaw(): RawAuthenticationResponse {
        requireMatchingCredentialIds(credentialId, rawId)
        return RawAuthenticationResponse(
            credentialId = CredentialId.fromBytes(rawId),
            clientDataJson = Base64UrlBytes.fromBytes(clientDataJson),
            authenticatorData = Base64UrlBytes.fromBytes(authenticatorData),
            signature = Base64UrlBytes.fromBytes(signature),
            userHandle = userHandle?.let { dev.webauthn.model.UserHandle.fromBytes(it) },
            authenticatorAttachment = authenticatorAttachment.toModel(),
            extensions = extensions,
        )
    }

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
            platformVersionHints = ["iosMajor=$major"],
        )
    }
}

private fun requireMatchingCredentialIds(credentialId: ByteArray, rawId: ByteArray) {
    require(credentialId.contentEquals(rawId)) { "credentialId must match rawId" }
}

private fun String?.toModel(): AuthenticatorAttachment? = when (this) {
    null -> null
    "platform" -> AuthenticatorAttachment.PLATFORM
    "cross-platform" -> AuthenticatorAttachment.CROSS_PLATFORM
    else -> throw IllegalArgumentException("Unsupported authenticator attachment: $this")
}
