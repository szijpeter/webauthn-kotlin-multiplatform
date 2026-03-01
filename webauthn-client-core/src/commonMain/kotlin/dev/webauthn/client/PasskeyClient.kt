package dev.webauthn.client

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.nonFatalOrThrow
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult

public interface PasskeyClient {
    public suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
    ): PasskeyResult<RegistrationResponse>

    public suspend fun getAssertion(
        options: PublicKeyCredentialRequestOptions,
    ): PasskeyResult<AuthenticationResponse>

    public suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
        return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("Raw create JSON API is not supported"))
    }

    public suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> {
        return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("Raw assertion JSON API is not supported"))
    }

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
    public suspend fun createCredential(requestJson: String): String

    public suspend fun getAssertion(requestJson: String): String

    public fun mapPlatformError(throwable: Throwable): PasskeyClientError

    public suspend fun capabilities(): PasskeyCapabilities {
        return PasskeyCapabilities()
    }
}

public interface PasskeyJsonCodec {
    public fun encodeCreationOptions(options: PublicKeyCredentialCreationOptions): String

    public fun decodeCreationOptions(payload: String): ValidationResult<PublicKeyCredentialCreationOptions>

    public fun encodeAssertionOptions(options: PublicKeyCredentialRequestOptions): String

    public fun decodeAssertionOptions(payload: String): ValidationResult<PublicKeyCredentialRequestOptions>

    public fun encodeRegistrationResponse(response: RegistrationResponse): String

    public fun decodeRegistrationResponse(payload: String): ValidationResult<RegistrationResponse>

    public fun encodeAuthenticationResponse(response: AuthenticationResponse): String

    public fun decodeAuthenticationResponse(payload: String): ValidationResult<AuthenticationResponse>
}

public class SharedPasskeyClient(
    private val bridge: PasskeyPlatformBridge,
    private val jsonCodec: PasskeyJsonCodec,
) : PasskeyClient {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        return runWithErrorMapping {
            requireCreationOptions(options)
            val requestPayload = encodeCreateOptions(options)
            val responsePayload = bridge.createCredential(requestPayload)
            decodeRegistrationResponse(responsePayload)
        }
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return runWithErrorMapping {
            val requestPayload = encodeAssertionOptions(options)
            val responsePayload = bridge.getAssertion(requestPayload)
            decodeAuthenticationResponse(responsePayload)
        }
    }

    override suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
        return runWithErrorMapping {
            val options = decodeCreationOptions(requestJson)
            requireCreationOptions(options)
            val requestPayload = encodeCreateOptions(options)
            val responsePayload = bridge.createCredential(requestPayload)
            val response = decodeRegistrationResponse(responsePayload)
            encodeRegistrationResponse(response)
        }
    }

    override suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> {
        return runWithErrorMapping {
            val options = decodeAssertionOptions(requestJson)
            val requestPayload = encodeAssertionOptions(options)
            val responsePayload = bridge.getAssertion(requestPayload)
            val response = decodeAuthenticationResponse(responsePayload)
            encodeAuthenticationResponse(response)
        }
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        return suspendCatching { bridge.capabilities() }
            .getOrElse { PasskeyCapabilities() }
    }

    private suspend fun <T> runWithErrorMapping(block: suspend () -> T): PasskeyResult<T> {
        return suspendCatching(block).fold(
            onSuccess = { PasskeyResult.Success(it) },
            onFailure = { error ->
                when (error) {
                    is InvalidOptionsException -> {
                        PasskeyResult.Failure(PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"))
                    }

                    is ResponseParseException -> {
                        PasskeyResult.Failure(
                            PasskeyClientError.Platform(
                                error.message ?: "Failed to parse platform response",
                                error.cause ?: error,
                            ),
                        )
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

    private fun decodeCreationOptions(payload: String): PublicKeyCredentialCreationOptions {
        val validation = fromCodecInvalidOptions("Failed to parse registration options JSON") {
            jsonCodec.decodeCreationOptions(payload)
        }
        return validation.toValueOrThrowInvalidOptions()
    }

    private fun encodeCreateOptions(options: PublicKeyCredentialCreationOptions): String {
        return fromCodecInvalidOptions("Failed to encode registration options") {
            jsonCodec.encodeCreationOptions(options)
        }
    }

    private fun decodeAssertionOptions(payload: String): PublicKeyCredentialRequestOptions {
        val validation = fromCodecInvalidOptions("Failed to parse authentication options JSON") {
            jsonCodec.decodeAssertionOptions(payload)
        }
        return validation.toValueOrThrowInvalidOptions()
    }

    private fun encodeAssertionOptions(options: PublicKeyCredentialRequestOptions): String {
        return fromCodecInvalidOptions("Failed to encode authentication options") {
            jsonCodec.encodeAssertionOptions(options)
        }
    }

    private fun decodeRegistrationResponse(payload: String): RegistrationResponse {
        val validation = fromCodecResponseParse("Failed to parse registration response JSON") {
            jsonCodec.decodeRegistrationResponse(payload)
        }
        return validation.toValueOrThrowResponseParse()
    }

    private fun encodeRegistrationResponse(response: RegistrationResponse): String {
        return fromCodecResponseParse("Failed to encode registration response JSON") {
            jsonCodec.encodeRegistrationResponse(response)
        }
    }

    private fun decodeAuthenticationResponse(payload: String): AuthenticationResponse {
        val validation = fromCodecResponseParse("Failed to parse authentication response JSON") {
            jsonCodec.decodeAuthenticationResponse(payload)
        }
        return validation.toValueOrThrowResponseParse()
    }

    private fun encodeAuthenticationResponse(response: AuthenticationResponse): String {
        return fromCodecResponseParse("Failed to encode authentication response JSON") {
            jsonCodec.encodeAuthenticationResponse(response)
        }
    }

    private inline fun <T> fromCodecInvalidOptions(message: String, block: () -> T): T {
        return catching(block)
            .mapFailure { error ->
                InvalidOptionsException(
                    "$message: ${error.message ?: "unknown error"}",
                    error,
                )
            }
            .getOrThrow()
    }

    private inline fun <T> fromCodecResponseParse(message: String, block: () -> T): T {
        return catching(block)
            .mapFailure { error ->
                ResponseParseException(
                    "$message: ${error.message ?: "unknown error"}",
                    error,
                )
            }
            .getOrThrow()
    }

    private fun <T> ValidationResult<T>.toValueOrThrowInvalidOptions(): T {
        return when (this) {
            is ValidationResult.Valid -> value
            is ValidationResult.Invalid -> throw InvalidOptionsException(firstValidationErrorMessage())
        }
    }

    private fun <T> ValidationResult<T>.toValueOrThrowResponseParse(): T {
        return when (this) {
            is ValidationResult.Valid -> value
            is ValidationResult.Invalid -> throw ResponseParseException(firstValidationErrorMessage())
        }
    }

    private fun ValidationResult.Invalid.firstValidationErrorMessage(): String {
        val firstError = errors.firstOrNull() ?: return "Unknown validation error"
        return "${firstError.field}: ${firstError.message}"
    }

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

private class ResponseParseException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

@ExperimentalWebAuthnL3Api
public data class PrfEvaluationRequest(
    public val enabled: Boolean,
)
