package dev.webauthn.client.swift

import dev.webauthn.client.DefaultJsonPasskeyClient
import dev.webauthn.client.JsonPasskeyClient
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.ios.IosPasskeyClient
import dev.webauthn.client.ios.MutablePasskeyPresentationAnchorProvider
import dev.webauthn.runtime.rethrowCancellationOrFatal
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import platform.Foundation.NSThread
import platform.UIKit.UIWindow

/** Internal Kotlin entry point consumed by the source-based WebAuthn Swift facade. */
public class SwiftPasskeyBridge private constructor(
    dependencies: SwiftBridgeDependencies,
) {
    private val anchorProvider: MutablePasskeyPresentationAnchorProvider = dependencies.anchorProvider
    private val passkeyClient: PasskeyClient = dependencies.passkeyClient
    private val jsonClient: JsonPasskeyClient = dependencies.jsonClient
    private val prfBridge: SwiftPrfBridge = dependencies.prfBridge
    private var operationInProgress: Boolean = false

    public constructor() : this(defaultDependencies())

    internal constructor(
        passkeyClient: PasskeyClient,
        jsonClient: JsonPasskeyClient,
    ) : this(testDependencies(passkeyClient, jsonClient))

    /** Updates the window used by the next AuthenticationServices ceremony. */
    public fun updatePresentationAnchor(window: UIWindow?) {
        check(NSThread.isMainThread) {
            "The presentation anchor must be updated on the main thread."
        }
        anchorProvider.update(window)
    }

    /** Executes registration from Kotlin-owned WebAuthn JSON decoding through response encoding. */
    public suspend fun createCredential(requestJson: String): SwiftPasskeyBridgeResult =
        runCeremony { jsonClient.createCredentialJson(requestJson).toBridgeResult() }

    /** Executes authentication from Kotlin-owned WebAuthn JSON decoding through response encoding. */
    public suspend fun getAssertion(requestJson: String): SwiftPasskeyBridgeResult =
        runCeremony { jsonClient.getAssertionJson(requestJson).toBridgeResult() }

    /** Authenticates with PRF and returns the response plus raw authenticator outputs. */
    @Suppress("TooGenericExceptionCaught")
    public suspend fun authenticateWithPrf(
        requestJson: String,
        firstSaltBase64Url: String,
        secondSaltBase64Url: String?,
    ): SwiftPrfAuthenticationBridgeResult {
        return try {
            runExclusive {
                prfBridge.authenticate(
                    requestJson = requestJson,
                    firstSaltBase64Url = firstSaltBase64Url,
                    secondSaltBase64Url = secondSaltBase64Url,
                )
            }
        } catch (_: OperationInProgressException) {
            prfFailure(
                code = "operationInProgress",
                message = "Another passkey ceremony is already in progress.",
            )
        } catch (error: Throwable) {
            error.rethrowCancellationOrFatal()
            prfFailure(
                code = "bridgeContract",
                message = "The internal PRF bridge failed.",
            )
        }
    }

    /** Returns the platform capability snapshot through a primitive JSON boundary. */
    public suspend fun capabilities(): SwiftPasskeyBridgeCapabilities =
        withContext(Dispatchers.Main.immediate) {
            passkeyClient.capabilities().toSwiftBridgeCapabilities()
        }

    internal suspend fun <T> runExclusive(block: suspend () -> T): T =
        withContext(Dispatchers.Main.immediate) {
            if (operationInProgress) {
                throw OperationInProgressException()
            }
            operationInProgress = true
            try {
                block()
            } finally {
                operationInProgress = false
            }
        }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun runCeremony(
        operation: suspend () -> SwiftPasskeyBridgeResult,
    ): SwiftPasskeyBridgeResult {
        return try {
            runExclusive(operation)
        } catch (_: OperationInProgressException) {
            failure(
                code = "operationInProgress",
                message = "Another passkey ceremony is already in progress.",
            )
        } catch (error: Throwable) {
            error.rethrowCancellationOrFatal()
            failure(
                code = "bridgeContract",
                message = "The internal passkey bridge failed.",
            )
        }
    }
}

private class OperationInProgressException : IllegalStateException()

private class SwiftBridgeDependencies(
    val anchorProvider: MutablePasskeyPresentationAnchorProvider,
    val passkeyClient: PasskeyClient,
    val jsonClient: JsonPasskeyClient,
    val prfBridge: SwiftPrfBridge,
)

private fun defaultDependencies(): SwiftBridgeDependencies {
    val anchorProvider = MutablePasskeyPresentationAnchorProvider()
    val passkeyClient = IosPasskeyClient(anchorProvider)
    val codec = KotlinxWebAuthnJsonCodec()
    return SwiftBridgeDependencies(
        anchorProvider = anchorProvider,
        passkeyClient = passkeyClient,
        jsonClient = DefaultJsonPasskeyClient(passkeyClient, codec),
        prfBridge = SwiftPrfBridge(passkeyClient, codec),
    )
}

private fun testDependencies(
    passkeyClient: PasskeyClient,
    jsonClient: JsonPasskeyClient,
): SwiftBridgeDependencies {
    val anchorProvider = MutablePasskeyPresentationAnchorProvider()
    return SwiftBridgeDependencies(
        anchorProvider = anchorProvider,
        passkeyClient = passkeyClient,
        jsonClient = jsonClient,
        prfBridge = SwiftPrfBridge(passkeyClient),
    )
}

private fun PasskeyResult<String>.toBridgeResult(): SwiftPasskeyBridgeResult = when (this) {
    is PasskeyResult.Success -> success(value)
    is PasskeyResult.Failure -> error.toSwiftBridgeFailure().let { failure ->
        failure(failure.code, failure.message)
    }
}
