@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.runtime.suspendCatchingNonCancellation
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.WebAuthnExtension

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
 * Capabilities are modeled as either a typed W3C WebAuthn [Extension] or a
 * [PlatformFeature] behavior.
 */
public sealed class PasskeyCapability {
    public abstract val key: String

    /** A capability that resolves directly to a specific W3C protocol extension identifier. */
    public data class Extension(
        public val extension: WebAuthnExtension,
    ) : PasskeyCapability() {
        override val key: String = extension.identifier
    }

    /** A capability that represents a literal platform transport or OS feature without a protocol payload. */
    public data class PlatformFeature(
        override val key: String,
    ) : PasskeyCapability()
}

/**
 * Capability hints surfaced by platform implementations.
 *
 * Use [supports] with a [PasskeyCapability] object to query a specific capability.
 * Extensions and platform bridges can advertise capabilities dynamically without modifying
 * this class.
 */
public data class PasskeyCapabilities(
    public val supported: Set<PasskeyCapability> = emptySet(),
    public val platformVersionHints: List<String> = emptyList(),
) {
    private val supportedByKey: Map<String, PasskeyCapability> = supported.associateBy(PasskeyCapability::key).also {
        require(it.size == supported.size) {
            "Duplicate capability keys are not allowed"
        }
    }

    /** Returns `true` if the given [capability] is supported. */
    public fun supports(capability: PasskeyCapability): Boolean = supportedByKey[capability.key] == capability

    /** Returns `true` if the given capability [key] is supported. */
    public fun supports(key: String): Boolean = key in supportedByKey
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
        return suspendCatchingNonCancellation(bridge::capabilities).getOrElse { PasskeyCapabilities() }
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
                    is InvalidOptionsException ->
                        PasskeyResult.Failure(PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"))
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
