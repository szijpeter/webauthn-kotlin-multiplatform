@file:Suppress("MaxLineLength")

package dev.webauthn.client.ios

import dev.webauthn.model.AttestationConveyancePreference
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ResidentKeyRequirement
import dev.webauthn.model.UserVerificationRequirement
import platform.AuthenticationServices.ASAuthorization
import platform.AuthenticationServices.ASAuthorizationController
import platform.AuthenticationServices.ASAuthorizationControllerDelegateProtocol
import platform.AuthenticationServices.ASAuthorizationControllerPresentationContextProvidingProtocol
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialProvider
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialRegistration
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialAssertion
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.AuthenticationServices.ASAuthorizationErrorUnknown
import platform.Foundation.NSError
import platform.UIKit.UIWindow
import platform.darwin.NSObject
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.useContents
import platform.Foundation.NSProcessInfo

internal class IosRegistrationPayload(
    val credentialId: ByteArray,
    val rawId: ByteArray,
    val attestationObject: ByteArray,
    val clientDataJson: ByteArray,
    val authenticatorAttachment: String? = null,
)

internal class IosAuthenticationPayload(
    val credentialId: ByteArray,
    val rawId: ByteArray,
    val authenticatorData: ByteArray,
    val signature: ByteArray,
    val clientDataJson: ByteArray,
    val userHandle: ByteArray?,
    val authenticatorAttachment: String? = null,
)

internal interface IosAuthorizationBridge {
    suspend fun createCredential(options: PublicKeyCredentialCreationOptions): IosRegistrationPayload
    suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): IosAuthenticationPayload
}

@OptIn(ExperimentalForeignApi::class)
internal class AuthenticationServicesAuthorizationBridge(
    private val windowProvider: () -> UIWindow
) : IosAuthorizationBridge {
    private val activeDelegates = mutableSetOf<Any>()

    /**
     * W3C WebAuthn L3: §5.1.3. Create a New Credential
     * Maps to Apple ASAuthorizationPlatformPublicKeyCredentialProvider createCredentialRegistrationRequestWithChallenge
     */
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): IosRegistrationPayload {
        return runAuthorizationRequest(
            buildRequests = {
                val requests = mutableListOf<Any>()

                val attachment = options.authenticatorAttachment
                val usePlatform = attachment == null || attachment == AuthenticatorAttachment.PLATFORM
                val useSecurityKey = attachment == null || attachment == AuthenticatorAttachment.CROSS_PLATFORM

                if (usePlatform) {
                    val provider = ASAuthorizationPlatformPublicKeyCredentialProvider(options.rp.id.value)
                    val request = provider.createCredentialRegistrationRequestWithChallenge(
                        options.challenge.value.bytes().toNSData(),
                        options.user.name,
                        options.user.id.value.bytes().toNSData(),
                    )
                    request.setUserVerificationPreference(options.userVerification.toPreferenceValue())
                    options.attestation?.let { request.setAttestationPreference(it.toPreferenceValue()) }
                    requests.add(request)
                }

                if (useSecurityKey && NSProcessInfo.processInfo.operatingSystemVersion.useContents { majorVersion.toInt() } >= 15) {
                    val provider = platform.AuthenticationServices.ASAuthorizationSecurityKeyPublicKeyCredentialProvider(options.rp.id.value)
                    val request = provider.createCredentialRegistrationRequestWithChallenge(
                        challenge = options.challenge.value.bytes().toNSData(),
                        displayName = options.user.displayName,
                        name = options.user.name,
                        userID = options.user.id.value.bytes().toNSData(),
                    )
                    request.setUserVerificationPreference(options.userVerification.toPreferenceValue())
                    options.attestation?.let { request.setAttestationPreference(it.toPreferenceValue()) }
                    requests.add(request)
                }

                check(requests.isNotEmpty()) { "No ASAuthorization providers available for the requested authenticatorAttachment" }
                requests
            },
            extractPayload = { credential ->
                when (credential) {
                    is ASAuthorizationPlatformPublicKeyCredentialRegistration -> {
                        IosRegistrationPayload(
                            credentialId = credential.credentialID.toByteArray(),
                            rawId = credential.credentialID.toByteArray(),
                            attestationObject = credential.rawAttestationObject?.toByteArray() ?: ByteArray(0),
                            clientDataJson = credential.rawClientDataJSON.toByteArray(),
                            authenticatorAttachment = "platform",
                        )
                    }
                    is platform.AuthenticationServices.ASAuthorizationSecurityKeyPublicKeyCredentialRegistration -> {
                        IosRegistrationPayload(
                            credentialId = credential.credentialID.toByteArray(),
                            rawId = credential.credentialID.toByteArray(),
                            attestationObject = credential.rawAttestationObject?.toByteArray() ?: ByteArray(0),
                            clientDataJson = credential.rawClientDataJSON.toByteArray(),
                            authenticatorAttachment = "cross-platform",
                        )
                    }
                    else -> throw unknownAuthorizationError()
                }
            },
        )
    }

    /**
     * W3C WebAuthn L3: §5.1.4. Use an Existing Credential to Make an Assertion
     * Maps to Apple ASAuthorizationPlatformPublicKeyCredentialProvider createCredentialAssertionRequestWithChallenge
     */
    @Suppress("ThrowsCount")
    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): IosAuthenticationPayload {
        val rpId = requireNotNull(options.rpId) {
            "PublicKeyCredentialRequestOptions.rpId is required by the iOS AuthenticationServices bridge."
        }
        return runAuthorizationRequest(
            buildRequests = {
                val requests = mutableListOf<Any>()

                // For assertion without attachment constraints we typically request both if possible
                val usePlatform = true
                val useSecurityKey = true

                if (usePlatform) {
                    val provider = ASAuthorizationPlatformPublicKeyCredentialProvider(rpId.value)
                    val request = provider.createCredentialAssertionRequestWithChallenge(
                        options.challenge.value.bytes().toNSData(),
                    )
                    request.setUserVerificationPreference(options.userVerification.toPreferenceValue())
                    requests.add(request)
                }

                if (useSecurityKey && NSProcessInfo.processInfo.operatingSystemVersion.useContents { majorVersion.toInt() } >= 15) {
                    val provider = platform.AuthenticationServices.ASAuthorizationSecurityKeyPublicKeyCredentialProvider(rpId.value)
                    val request = provider.createCredentialAssertionRequestWithChallenge(
                        options.challenge.value.bytes().toNSData(),
                    )
                    request.setUserVerificationPreference(options.userVerification.toPreferenceValue())
                    requests.add(request)
                }

                check(requests.isNotEmpty()) { "No ASAuthorization providers available" }
                requests
            },
            extractPayload = { credential ->
                when (credential) {
                    is ASAuthorizationPlatformPublicKeyCredentialAssertion -> {
                        IosAuthenticationPayload(
                            credentialId = credential.credentialID.toByteArray(),
                            rawId = credential.credentialID.toByteArray(),
                            authenticatorData = checkNotNull(
                                value = credential.rawAuthenticatorData?.toByteArray(),
                            ) { "Missing rawAuthenticatorData in assertion response" },
                            signature = credential.signature?.toByteArray()
                                ?: throw IllegalStateException("Missing signature in assertion response"),
                            clientDataJson = credential.rawClientDataJSON.toByteArray(),
                            userHandle = credential.userID?.toByteArray(),
                            authenticatorAttachment = "platform",
                        )
                    }
                    is platform.AuthenticationServices.ASAuthorizationSecurityKeyPublicKeyCredentialAssertion -> {
                        IosAuthenticationPayload(
                            credentialId = credential.credentialID.toByteArray(),
                            rawId = credential.credentialID.toByteArray(),
                            authenticatorData = credential.rawAuthenticatorData?.toByteArray()
                                ?: throw IllegalStateException("Missing rawAuthenticatorData in assertion response"),
                            signature = credential.signature?.toByteArray()
                                ?: throw IllegalStateException("Missing signature in assertion response"),
                            clientDataJson = credential.rawClientDataJSON.toByteArray(),
                            userHandle = credential.userID?.toByteArray(),
                            authenticatorAttachment = "cross-platform",
                        )
                    }
                    else -> throw unknownAuthorizationError()
                }
            },
        )
    }

    @OptIn(ExperimentalForeignApi::class)
    @Suppress("TooGenericExceptionCaught")
    private suspend fun <TPayload> runAuthorizationRequest(
        buildRequests: () -> List<Any>,
        extractPayload: (Any?) -> TPayload,
    ): TPayload {
        return suspendCancellableCoroutine { continuation ->
            val requests = buildRequests()
            val controller = ASAuthorizationController(requests)
            var retainedDelegate: Any? = null
            fun releaseDelegate() {
                retainedDelegate?.let {
                    activeDelegates.remove(it)
                    retainedDelegate = null
                }
            }
            fun complete(payload: TPayload? = null, error: Throwable? = null) {
                releaseDelegate()
                if (!continuation.isActive) return
                if (error != null) {
                    continuation.resumeWithException(error)
                } else {
                    @Suppress("UNCHECKED_CAST")
                    continuation.resume(payload as TPayload)
                }
            }

            val delegate = object : NSObject(),
                ASAuthorizationControllerDelegateProtocol,
                ASAuthorizationControllerPresentationContextProvidingProtocol {
                override fun presentationAnchorForAuthorizationController(
                    controller: ASAuthorizationController)
                : UIWindow {
                    return windowProvider()
                }

                override fun authorizationController(
                    controller: ASAuthorizationController,
                    didCompleteWithAuthorization: ASAuthorization,
                ) {
                    try {
                        complete(payload = extractPayload(didCompleteWithAuthorization.credential))
                    } catch (error: Exception) {
                        complete(error = error)
                    }
                }

                override fun authorizationController(
                    controller: ASAuthorizationController,
                    didCompleteWithError: NSError,
                ) {
                    complete(error = NSErrorException(didCompleteWithError))
                }
            }
            retainedDelegate = delegate
            activeDelegates += delegate
            controller.delegate = delegate
            controller.presentationContextProvider = delegate
            continuation.invokeOnCancellation {
                releaseDelegate()
                controller.cancel()
            }
            controller.performRequests()
        }
    }

    private fun unknownAuthorizationError(): NSErrorException =
        NSErrorException(NSError.errorWithDomain(ASAuthorizationErrorDomain, ASAuthorizationErrorUnknown, null))
}

private fun UserVerificationRequirement.toPreferenceValue(): String = when (this) {
    UserVerificationRequirement.REQUIRED -> "required"
    UserVerificationRequirement.PREFERRED -> "preferred"
    UserVerificationRequirement.DISCOURAGED -> "discouraged"
}

private fun ResidentKeyRequirement.toPreferenceValue(): String = when (this) {
    ResidentKeyRequirement.REQUIRED -> "required"
    ResidentKeyRequirement.PREFERRED -> "preferred"
    ResidentKeyRequirement.DISCOURAGED -> "discouraged"
}

private fun AttestationConveyancePreference.toPreferenceValue(): String {
    return name.lowercase()
}
