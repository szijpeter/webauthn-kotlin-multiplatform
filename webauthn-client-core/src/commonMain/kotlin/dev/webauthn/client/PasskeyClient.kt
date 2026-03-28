@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.runtime.suspendCatchingNonCancellation
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

/** Public cross-platform API for WebAuthn registration and authentication ceremonies. */
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

/**
 * Represents a capability or extension that a passkey client, platform bridge,
 * or authenticator might support.
 *
 * Known standard capabilities are defined as objects, while new or proprietary
 * capabilities can be defined using [Custom].
 */
public sealed class PasskeyCapability(public val key: String) {
    /** W3C WebAuthn L3: §9.2.1. HMAC Secret Extension (prf) */
    public object Prf : PasskeyCapability("prf")

    /** W3C WebAuthn L3: §9.2.2. Large blob storage extension — read support. */
    public object LargeBlobRead : PasskeyCapability("largeBlobRead")

    /** W3C WebAuthn L3: §9.2.2. Large blob storage extension — write support. */
    public object LargeBlobWrite : PasskeyCapability("largeBlobWrite")

    /** Platform transport capability: security key (cross-platform authenticator) support. */
    public object SecurityKey : PasskeyCapability("securityKey")

    /** Fallback for proprietary or draft extensions not yet modeled in the core. */
    public class Custom(key: String) : PasskeyCapability(key) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PasskeyCapability) return false
            return key == other.key
        }
        override fun hashCode(): Int = key.hashCode()
    }
}

/**
 * Capability hints surfaced by platform implementations.
 *
 * Use [supports] with a [PasskeyCapability] object to query a specific capability.
 * Extensions and platform bridges can advertise capabilities dynamically without modifying
 * this class.
 */
public data class PasskeyCapabilities(
    public val capabilities: Map<String, Boolean> = emptyMap(),
    public val platformVersionHints: List<String> = emptyList(),
) {
    /** Returns `true` if the given [capability] is supported. */
    public fun supports(capability: PasskeyCapability): Boolean = capabilities[capability.key] == true

    /** Returns `true` if the given capability [key] is supported. */
    public fun supports(key: String): Boolean = capabilities[key] == true
}

/** Result wrapper for passkey operations. */
public sealed interface PasskeyResult<out T> {
    public data class Success<T>(public val value: T) : PasskeyResult<T>

    public data class Failure(public val error: PasskeyClientError) : PasskeyResult<Nothing>
}

/** Error surface returned by passkey operations. */
public sealed interface PasskeyClientError {
    public val message: String

    public data class UserCancelled(
        override val message: String = "The user cancelled the passkey prompt",
    ) : PasskeyClientError

    public data class InvalidOptions(override val message: String) : PasskeyClientError

    public data class Transport(override val message: String, public val cause: Throwable? = null) : PasskeyClientError

    public data class Platform(override val message: String, public val cause: Throwable? = null) : PasskeyClientError
}

/** Platform bridge contract implemented by target-specific modules. */
public interface PasskeyPlatformBridge {
    public suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse

    public suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse

    public fun mapPlatformError(throwable: Throwable): PasskeyClientError

    public suspend fun capabilities(): PasskeyCapabilities {
        return PasskeyCapabilities()
    }
}

/** Default [PasskeyClient] orchestration that delegates to a platform bridge. */
public class DefaultPasskeyClient(
    private val bridge: PasskeyPlatformBridge,
) : PasskeyClient {
    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse> {
        return runTypedCeremony(
            options = options,
            validate = ::requireCreationOptions,
            operation = bridge::createCredential,
        )
    }

    override suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse> {
        return runTypedCeremony(
            options = options,
            operation = bridge::getAssertion,
        )
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        return suspendCatchingNonCancellation(bridge::capabilities).fold(
            onSuccess = { it },
            onFailure = { _ ->
                PasskeyCapabilities()
            },
        )
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
        return suspendCatchingNonCancellation(block).fold(
            onSuccess = { PasskeyResult.Success(it) },
            onFailure = { error ->
                when (error) {
                    is InvalidOptionsException ->
                        PasskeyResult.Failure(PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"))
                    is IllegalArgumentException ->
                        mapIllegalArgumentWithBridge(error)

                    else -> PasskeyResult.Failure(bridge.mapPlatformError(error))
                }
            },
        )
    }

    private fun mapIllegalArgumentWithBridge(error: IllegalArgumentException): PasskeyResult.Failure {
        return PasskeyResult.Failure(bridge.mapPlatformError(error))
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

