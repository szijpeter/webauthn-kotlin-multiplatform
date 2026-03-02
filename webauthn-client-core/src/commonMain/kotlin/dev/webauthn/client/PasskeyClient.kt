package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import kotlinx.coroutines.CancellationException

public interface PasskeyClient {
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse>

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
        return runWithErrorMapping {
            requireCreationOptions(options)
            bridge.createCredential(options)
        }
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return runWithErrorMapping { bridge.getAssertion(options) }
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        return try {
            bridge.capabilities()
        } catch (error: Throwable) {
            when (error) {
                is CancellationException,
                is Error -> throw error
                else -> PasskeyCapabilities()
            }
        }
    }

    private suspend fun <T> runWithErrorMapping(block: suspend () -> T): PasskeyResult<T> {
        return try {
            PasskeyResult.Success(block())
        } catch (error: Throwable) {
            when (error) {
                is CancellationException,
                is Error -> throw error
                is InvalidOptionsException,
                is IllegalArgumentException -> PasskeyResult.Failure(
                    PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"),
                )

                else -> PasskeyResult.Failure(bridge.mapPlatformError(error))
            }
        }
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

@ExperimentalWebAuthnL3Api
public data class PrfEvaluationRequest(
    public val enabled: Boolean,
)
