package dev.webauthn.client

import at.asitplus.KmmResult
import at.asitplus.nonFatalOrThrow
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

public interface PasskeyClient {
    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.create)
     */
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse>

    /**
     * W3C WebAuthn L3: §5.1. Authentication Credentials Container (navigator.credentials.get)
     */
    public suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse>

    public suspend fun capabilities(): PasskeyCapabilities {
        return PasskeyCapabilities()
    }
}

public data class PasskeyCapabilities(
    public val supportsPrf: Boolean = false,
    public val supportsLargeBlobRead: Boolean = false,
    public val supportsLargeBlobWrite: Boolean = false,
    public val supportsSecurityKey: Boolean = false,
    public val platformVersionHints: List<String> = emptyList(),
)

public sealed interface PasskeyResult<out T> {
    public data class Success<T>(public val value: T) : PasskeyResult<T>

    public data class Failure(public val error: PasskeyClientError) : PasskeyResult<Nothing>
}

public sealed interface PasskeyClientError {
    public val message: String

    public data class UserCancelled(override val message: String = "The user cancelled the passkey prompt") : PasskeyClientError

    public data class InvalidOptions(override val message: String) : PasskeyClientError

    public data class Transport(override val message: String, public val cause: Throwable? = null) : PasskeyClientError

    public data class Platform(override val message: String, public val cause: Throwable? = null) : PasskeyClientError
}

public interface PasskeyPlatformBridge {
    public suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse

    public suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse

    public fun mapPlatformError(throwable: Throwable): PasskeyClientError

    public suspend fun capabilities(): PasskeyCapabilities {
        return PasskeyCapabilities()
    }
}

public class DefaultPasskeyClient(
    private val bridge: PasskeyPlatformBridge,
) : PasskeyClient {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return runTypedCeremony(
            options = options,
            validate = ::requireCreationOptions,
            operation = bridge::createCredential,
        )
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return runTypedCeremony(
            options = options,
            operation = bridge::getAssertion,
        )
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        return suspendCatching { bridge.capabilities() }
            .getOrElse { PasskeyCapabilities() }
    }

    private suspend fun <TOptions, TResult> runTypedCeremony(
        options: TOptions,
        validate: (TOptions) -> Unit = {},
        operation: suspend (TOptions) -> TResult,
    ): PasskeyResult<TResult> {
        return runWithErrorMapping {
            validate(options)
            operation(options)
        }
    }

    private suspend fun <T> runWithErrorMapping(block: suspend () -> T): PasskeyResult<T> {
        return suspendCatching(block).fold(
            onSuccess = { PasskeyResult.Success(it) },
            onFailure = { error ->
                when (error) {
                    is InvalidOptionsException,
                    is IllegalArgumentException -> {
                        PasskeyResult.Failure(PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"))
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

    @Suppress("TooGenericExceptionCaught")
    private suspend fun <T> suspendCatching(block: suspend () -> T): KmmResult<T> {
        return try {
            KmmResult(block())
        } catch (error: Throwable) {
            KmmResult(error.nonFatalOrThrow())
        }
    }
}

private class InvalidOptionsException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

@ExperimentalWebAuthnL3Api
public data class PrfEvaluationRequest(
    public val enabled: Boolean,
)
