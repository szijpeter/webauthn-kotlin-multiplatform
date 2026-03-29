@file:Suppress("MaxLineLength", "TooManyFunctions")

package dev.webauthn.client.ios

import dev.webauthn.model.AttestationConveyancePreference
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ResidentKeyRequirement
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.ValidationResult
import platform.AuthenticationServices.ASAuthorization
import platform.AuthenticationServices.ASAuthorizationController
import platform.AuthenticationServices.ASAuthorizationControllerDelegateProtocol
import platform.AuthenticationServices.ASAuthorizationControllerPresentationContextProvidingProtocol
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialProvider
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialRegistration
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialAssertion
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
import platform.AuthenticationServices.ASAuthorizationPublicKeyCredentialPRFAssertionInput
import platform.AuthenticationServices.ASAuthorizationPublicKeyCredentialPRFAssertionInputValues
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.AuthenticationServices.ASAuthorizationErrorUnknown
import platform.Foundation.NSClassFromString
import platform.Foundation.NSError
import platform.UIKit.UIWindow
import platform.darwin.NSObject
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.useContents
import platform.Foundation.NSProcessInfo

private const val MIN_PRF_IOS_VERSION = 18
private const val MIN_SECURITY_KEY_IOS_VERSION = 15

internal data class PrfAssertionInputShape(
    val eval: AuthenticationExtensionsPRFValues?,
    val evalByCredential: Map<Base64UrlBytes, AuthenticationExtensionsPRFValues>?,
)

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
    val extensions: AuthenticationExtensionsClientOutputs? = null,
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
                val iosMajorVersion = currentIosMajorVersion()
                val usePlatform = shouldIncludePlatformRegistrationRequest(attachment)
                val useSecurityKey = shouldIncludeSecurityKeyRegistrationRequest(
                    authenticatorAttachment = attachment,
                    iosMajorVersion = iosMajorVersion,
                )

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

                if (useSecurityKey) {
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
        val prfInput = shapePrfAssertionInput(options.extensions?.prf)
        val prfRequested = isPrfRequested(prfInput)
        if (prfRequested && !isPrfRuntimeSupported()) {
            throw IllegalArgumentException(
                "PRF extension requires iOS $MIN_PRF_IOS_VERSION+ with AuthenticationServices PRF APIs.",
            )
        }
        return runAuthorizationRequest(
            buildRequests = {
                buildAssertionRequests(
                    options = options,
                    rpId = rpId.value,
                    prfInput = prfInput,
                    prfRequested = prfRequested,
                )
            },
            extractPayload = ::extractAssertionPayload,
        )
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun buildAssertionRequests(
        options: PublicKeyCredentialRequestOptions,
        rpId: String,
        prfInput: PrfAssertionInputShape?,
        prfRequested: Boolean,
    ): List<Any> {
        val requests = mutableListOf<Any>()
        val platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(rpId)
        val platformRequest = platformProvider.createCredentialAssertionRequestWithChallenge(
            options.challenge.value.bytes().toNSData(),
        )
        platformRequest.setUserVerificationPreference(options.userVerification.toPreferenceValue())
        if (prfInput != null) {
            platformRequest.setPrfInput(prfInput)
        }
        requests.add(platformRequest)

        if (shouldIncludeSecurityKeyAssertionRequest(prfRequested, currentIosMajorVersion())) {
            val securityProvider = platform.AuthenticationServices.ASAuthorizationSecurityKeyPublicKeyCredentialProvider(rpId)
            val securityRequest = securityProvider.createCredentialAssertionRequestWithChallenge(
                options.challenge.value.bytes().toNSData(),
            )
            securityRequest.setUserVerificationPreference(options.userVerification.toPreferenceValue())
            requests.add(securityRequest)
        }

        check(requests.isNotEmpty()) { "No ASAuthorization providers available" }
        return requests
    }

    private fun extractAssertionPayload(credential: Any?): IosAuthenticationPayload {
        return when (credential) {
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
                    extensions = credential.prfExtensionsOrNull(),
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
                    extensions = null,
                )
            }
            else -> throw unknownAuthorizationError()
        }
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

internal fun shouldIncludeSecurityKeyAssertionRequest(
    prfRequested: Boolean,
    iosMajorVersion: Int,
): Boolean {
    return !prfRequested && iosMajorVersion >= MIN_SECURITY_KEY_IOS_VERSION
}

internal fun shouldIncludePlatformRegistrationRequest(
    authenticatorAttachment: AuthenticatorAttachment?,
): Boolean {
    return authenticatorAttachment == null || authenticatorAttachment == AuthenticatorAttachment.PLATFORM
}

internal fun shouldIncludeSecurityKeyRegistrationRequest(
    authenticatorAttachment: AuthenticatorAttachment?,
    iosMajorVersion: Int,
): Boolean {
    return authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM &&
        iosMajorVersion >= MIN_SECURITY_KEY_IOS_VERSION
}

internal fun isPrfRequested(prfInput: PrfAssertionInputShape?): Boolean {
    return prfInput != null
}

internal fun shapePrfAssertionInput(prfInput: PrfExtensionInput?): PrfAssertionInputShape? {
    if (prfInput == null) return null
    val evalByCredential = prfInput.evalByCredential
        ?.mapKeys(::parsePrfCredentialIdEntryOrThrow)
        ?.takeUnless(Map<Base64UrlBytes, AuthenticationExtensionsPRFValues>::isEmpty)
    if (prfInput.eval == null && evalByCredential == null) return null
    return PrfAssertionInputShape(
        eval = prfInput.eval,
        evalByCredential = evalByCredential,
    )
}

private fun parsePrfCredentialIdEntryOrThrow(
    entry: Map.Entry<String, AuthenticationExtensionsPRFValues>,
): Base64UrlBytes = parsePrfCredentialIdKeyOrThrow(entry.key)

private fun parsePrfCredentialIdKeyOrThrow(encodedCredentialId: String): Base64UrlBytes {
    if (encodedCredentialId.isEmpty()) {
        throw IllegalArgumentException(
            "PRF extension `evalByCredential` credential ID keys must be non-empty base64url values.",
        )
    }
    return when (val parsed = Base64UrlBytes.parse(encodedCredentialId, "extensions.prf.evalByCredential")) {
        is ValidationResult.Valid -> parsed.value
        is ValidationResult.Invalid -> {
            val message = parsed.errors.joinToString(separator = "; ") { it.message }
            throw IllegalArgumentException(
                "PRF extension `evalByCredential` contains invalid credential ID key `$encodedCredentialId`: $message",
            )
        }
    }
}

private fun ASAuthorizationPlatformPublicKeyCredentialAssertionRequest.setPrfInput(
    values: PrfAssertionInputShape,
) {
    val inputValues = values.eval?.toPlatformPrfInputValues()
    val perCredentialInputValues: Map<Any?, *>? = values.evalByCredential
        ?.mapKeys(::credentialIdEntryToNSData)
        ?.mapValues { (_, prfValues) -> prfValues.toPlatformPrfInputValues() }
    prf = ASAuthorizationPublicKeyCredentialPRFAssertionInput(inputValues, perCredentialInputValues)
}

private fun credentialIdEntryToNSData(
    entry: Map.Entry<Base64UrlBytes, AuthenticationExtensionsPRFValues>,
): Any = entry.key.bytes().toNSData()

private fun AuthenticationExtensionsPRFValues.toPlatformPrfInputValues():
    ASAuthorizationPublicKeyCredentialPRFAssertionInputValues {
    return ASAuthorizationPublicKeyCredentialPRFAssertionInputValues(
        saltInput1 = first.bytes().toNSData(),
        saltInput2 = second?.bytes()?.toNSData(),
    )
}

private fun ASAuthorizationPlatformPublicKeyCredentialAssertion.prfExtensionsOrNull(): AuthenticationExtensionsClientOutputs? {
    if (!isPrfRuntimeSupported()) return null
    val output = prf() ?: return null
    val first = Base64UrlBytes.fromBytes(output.first.toByteArray())
    val second = output.second?.toByteArray()?.let(Base64UrlBytes::fromBytes)
    return AuthenticationExtensionsClientOutputs(
        prf = PrfExtensionOutput(
            enabled = true,
            results = AuthenticationExtensionsPRFValues(first = first, second = second),
        ),
    )
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
private fun currentIosMajorVersion(): Int {
    return NSProcessInfo.processInfo.operatingSystemVersion.useContents { majorVersion.toInt() }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
private fun isPrfRuntimeSupported(): Boolean {
    val version = currentIosMajorVersion()
    if (version < MIN_PRF_IOS_VERSION) return false
    return NSClassFromString("ASAuthorizationPublicKeyCredentialPRFAssertionInput") != null
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
