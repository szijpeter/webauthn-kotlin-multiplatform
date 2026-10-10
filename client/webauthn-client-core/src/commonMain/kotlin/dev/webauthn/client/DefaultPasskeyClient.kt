@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.runtime.suspendCatchingNonCancellation

/** Default [PasskeyClient] orchestration that delegates to a platform bridge. */
public class DefaultPasskeyClient(
    private val bridge: PasskeyPlatformBridge,
) : PasskeyClient {
    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RawRegistrationResponse> {
        return runOperation(
            options = options,
            validate = ::requireCreationOptions,
            operation = bridge::createCredential,
        )
    }

    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
        createOptions: PasskeyCreateOptions,
    ): PasskeyResult<RawRegistrationResponse> {
        return runOperation(
            options = options,
            validate = ::requireCreationOptions,
            operation = { bridge.createCredential(it, createOptions) },
        )
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<RawAuthenticationResponse> {
        return runOperation(
            options = options,
            operation = bridge::getAssertion,
        )
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        return suspendCatchingNonCancellation(bridge::capabilities)
            .getOrElse { PasskeyCapabilities() }
    }

    private suspend fun <TOptions, TResult> runOperation(
        options: TOptions,
        validate: (TOptions) -> Unit = {},
        operation: suspend (TOptions) -> TResult,
    ): PasskeyResult<TResult> {
        try {
            validate(options)
        } catch (error: IllegalArgumentException) {
            return PasskeyResult.Failure(
                PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"),
            )
        }

        return suspendCatchingNonCancellation { operation(options) }.fold(
            onSuccess = { PasskeyResult.Success(it) },
            onFailure = { error -> PasskeyResult.Failure(bridge.mapPlatformError(error)) },
        )
    }

    private fun requireCreationOptions(options: PublicKeyCredentialCreationOptions) {
        if (options.pubKeyCredParams.isEmpty()) {
            throw InvalidOptionsException("pubKeyCredParams must not be empty")
        }
    }
}

private class InvalidOptionsException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)
