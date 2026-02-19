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
)

internal data class IosAuthenticationPayload(
    val credentialId: ByteArray,
    val rawId: ByteArray,
    val authenticatorData: ByteArray,
    val signature: ByteArray,
    val clientDataJson: ByteArray,
    val userHandle: ByteArray?,
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
        return suspendCancellableCoroutine { continuation ->
            val provider = ASAuthorizationPlatformPublicKeyCredentialProvider(options.rp.id.value)
            val request = provider.createCredentialRegistrationRequestWithChallenge(options.challenge.value.bytes().toNSData(), options.user.name, options.user.id.value.bytes().toNSData())
            
            val controller = ASAuthorizationController(listOf(request))
            var retainedDelegate: Any? = null
            val releaseDelegate: () -> Unit = {
                retainedDelegate?.let {
                    activeDelegates.remove(it)
                    retainedDelegate = null
                }
            }
            val delegate = object : NSObject(), ASAuthorizationControllerDelegateProtocol, ASAuthorizationControllerPresentationContextProvidingProtocol {
                override fun presentationAnchorForAuthorizationController(controller: ASAuthorizationController): UIWindow {
                    return windowProvider()
                }

                override fun authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization: ASAuthorization) {
                    val credential = didCompleteWithAuthorization.credential
                    if (credential is ASAuthorizationPlatformPublicKeyCredentialRegistration) {
                        try {
                            val payload = IosRegistrationPayload(
                                credentialId = credential.credentialID.toByteArray(),
                                rawId = credential.credentialID.toByteArray(),
                                attestationObject = credential.rawAttestationObject?.toByteArray() ?: ByteArray(0),
                                clientDataJson = credential.rawClientDataJSON.toByteArray()
                            )
                            releaseDelegate()
                            if (continuation.isActive) {
                                continuation.resume(payload)
                            }
                        } catch (e: Exception) {
                            releaseDelegate()
                            if (continuation.isActive) {
                                continuation.resumeWithException(e)
                            }
                        }
                    } else {
                        val error = NSError.errorWithDomain(ASAuthorizationErrorDomain, ASAuthorizationErrorUnknown, null)
                        releaseDelegate()
                        if (continuation.isActive) {
                            continuation.resumeWithException(NSErrorException(error))
                        }
                    }
                }

                override fun authorizationController(controller: ASAuthorizationController, didCompleteWithError: NSError) {
                    releaseDelegate()
                    if (continuation.isActive) {
                        continuation.resumeWithException(NSErrorException(didCompleteWithError))
                    }
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

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): IosAuthenticationPayload {
        return suspendCancellableCoroutine { continuation ->
            val provider = ASAuthorizationPlatformPublicKeyCredentialProvider(options.rpId.value)
            val request = provider.createCredentialAssertionRequestWithChallenge(options.challenge.value.bytes().toNSData())
            
            val controller = ASAuthorizationController(listOf(request))
            var retainedDelegate: Any? = null
            val releaseDelegate: () -> Unit = {
                retainedDelegate?.let {
                    activeDelegates.remove(it)
                    retainedDelegate = null
                }
            }
            val delegate = object : NSObject(), ASAuthorizationControllerDelegateProtocol, ASAuthorizationControllerPresentationContextProvidingProtocol {
                override fun presentationAnchorForAuthorizationController(controller: ASAuthorizationController): UIWindow {
                    return windowProvider()
                }

                override fun authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization: ASAuthorization) {
                    val credential = didCompleteWithAuthorization.credential
                    if (credential is ASAuthorizationPlatformPublicKeyCredentialAssertion) {
                        try {
                            val payload = IosAuthenticationPayload(
                                credentialId = credential.credentialID.toByteArray(),
                                rawId = credential.credentialID.toByteArray(),
                                authenticatorData = credential.rawAuthenticatorData?.toByteArray()
                                    ?: throw IllegalStateException("Missing rawAuthenticatorData in assertion response"),
                                signature = credential.signature?.toByteArray()
                                    ?: throw IllegalStateException("Missing signature in assertion response"),
                                clientDataJson = credential.rawClientDataJSON.toByteArray(),
                                userHandle = credential.userID?.toByteArray()
                            )
                            releaseDelegate()
                            if (continuation.isActive) {
                                continuation.resume(payload)
                            }
                        } catch (e: Exception) {
                            releaseDelegate()
                            if (continuation.isActive) {
                                continuation.resumeWithException(e)
                            }
                        }
                    } else {
                        val error = NSError.errorWithDomain(ASAuthorizationErrorDomain, ASAuthorizationErrorUnknown, null)
                        releaseDelegate()
                        if (continuation.isActive) {
                            continuation.resumeWithException(NSErrorException(error))
                        }
                    }
                }

                override fun authorizationController(controller: ASAuthorizationController, didCompleteWithError: NSError) {
                    releaseDelegate()
                    if (continuation.isActive) {
                        continuation.resumeWithException(NSErrorException(didCompleteWithError))
                    }
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
}
