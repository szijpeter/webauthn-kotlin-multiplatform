@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.runtime.suspendCatchingNonCancellation

/** Default [PasskeyClient] orchestration that delegates to a platform bridge. */
public class DefaultPasskeyClient(
    private val bridge: PasskeyPlatformBridge,
) : PasskeyClient {
    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        return runOperation(
            options = options,
            validate = ::requireCreationOptions,
            operation = bridge::createCredential,
        )
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
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
        return suspendCatchingNonCancellation {
            validate(options)
            operation(options)
        }.fold(
            onSuccess = { PasskeyResult.Success(it) },
            onFailure = { error ->
                when (error) {
                    is IllegalArgumentException -> {
                        val mapped = bridge.mapPlatformError(error)
                        val message = mapped.message.ifBlank { error.message ?: "Invalid options" }
                        PasskeyResult.Failure(PasskeyClientError.InvalidOptions(message))
                    }

                    else -> PasskeyResult.Failure(bridge.mapPlatformError(error))
                }
            },
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
