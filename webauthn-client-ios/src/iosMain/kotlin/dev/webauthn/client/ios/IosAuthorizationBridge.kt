package dev.webauthn.client.ios

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
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

internal data class IosRegistrationPayload(
    val credentialId: ByteArray,
    val rawId: ByteArray,
    val attestationObject: ByteArray,
    val clientDataJson: ByteArray,
    val authenticatorAttachment: String? = null,
)

internal data class IosAuthenticationPayload(
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

internal class AuthenticationServicesAuthorizationBridge(
    private val windowProvider: () -> UIWindow
) : IosAuthorizationBridge {
    private val activeDelegates = mutableSetOf<Any>()

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): IosRegistrationPayload {
        return runAuthorizationRequest(
            buildRequest = {
                val provider = ASAuthorizationPlatformPublicKeyCredentialProvider(options.rp.id.value)
                val request = provider.createCredentialRegistrationRequestWithChallenge(
                    options.challenge.value.bytes().toNSData(),
                    options.user.name,
                    options.user.id.value.bytes().toNSData(),
                )
                request.setUserVerificationPreference(options.userVerification.toPreferenceValue())
                options.attestation?.let { request.setAttestationPreference(it.toPreferenceValue()) }
                request
            },
            extractPayload = { credential ->
                val registration = credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration
                    ?: throw unknownAuthorizationError()
                IosRegistrationPayload(
                    credentialId = registration.credentialID.toByteArray(),
                    rawId = registration.credentialID.toByteArray(),
                    attestationObject = registration.rawAttestationObject?.toByteArray() ?: ByteArray(0),
                    clientDataJson = registration.rawClientDataJSON.toByteArray(),
                    authenticatorAttachment = "platform",
                )
            },
        )
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): IosAuthenticationPayload {
        return runAuthorizationRequest(
            buildRequest = {
                val provider = ASAuthorizationPlatformPublicKeyCredentialProvider(options.rpId.value)
                val request = provider.createCredentialAssertionRequestWithChallenge(
                    options.challenge.value.bytes().toNSData(),
                )
                request.setUserVerificationPreference(options.userVerification.toPreferenceValue())
                request
            },
            extractPayload = { credential ->
                val assertion = credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion
                    ?: throw unknownAuthorizationError()
                IosAuthenticationPayload(
                    credentialId = assertion.credentialID.toByteArray(),
                    rawId = assertion.credentialID.toByteArray(),
                    authenticatorData = assertion.rawAuthenticatorData?.toByteArray()
                        ?: throw IllegalStateException("Missing rawAuthenticatorData in assertion response"),
                    signature = assertion.signature?.toByteArray()
                        ?: throw IllegalStateException("Missing signature in assertion response"),
                    clientDataJson = assertion.rawClientDataJSON.toByteArray(),
                    userHandle = assertion.userID?.toByteArray(),
                    authenticatorAttachment = "platform",
                )
            },
        )
    }

    private suspend fun <TPayload> runAuthorizationRequest(
        buildRequest: () -> Any,
        extractPayload: (Any?) -> TPayload,
    ): TPayload {
        return suspendCancellableCoroutine { continuation ->
            val request = buildRequest()
            val controller = ASAuthorizationController(listOf(request))
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

            val delegate = object : NSObject(), ASAuthorizationControllerDelegateProtocol, ASAuthorizationControllerPresentationContextProvidingProtocol {
                override fun presentationAnchorForAuthorizationController(controller: ASAuthorizationController): UIWindow {
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

private fun dev.webauthn.model.UserVerificationRequirement.toPreferenceValue(): String = when (this) {
    dev.webauthn.model.UserVerificationRequirement.REQUIRED -> "required"
    dev.webauthn.model.UserVerificationRequirement.PREFERRED -> "preferred"
    dev.webauthn.model.UserVerificationRequirement.DISCOURAGED -> "discouraged"
}

private fun dev.webauthn.model.ResidentKeyRequirement.toPreferenceValue(): String = when (this) {
    dev.webauthn.model.ResidentKeyRequirement.REQUIRED -> "required"
    dev.webauthn.model.ResidentKeyRequirement.PREFERRED -> "preferred"
    dev.webauthn.model.ResidentKeyRequirement.DISCOURAGED -> "discouraged"
}

private fun dev.webauthn.model.AttestationConveyancePreference.toPreferenceValue(): String {
    return name.lowercase()
}
