package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

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

public interface JsonPasskeyClient {
    public suspend fun createCredentialJson(requestJson: String): PasskeyResult<String>

    public suspend fun getAssertionJson(requestJson: String): PasskeyResult<String>
}

public class DefaultJsonPasskeyClient(
    private val passkeyClient: PasskeyClient,
    private val jsonCodec: PasskeyJsonCodec = KotlinxPasskeyJsonCodec(),
) : JsonPasskeyClient {
    override suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = ::decodeCreationOptions,
            execute = { options -> passkeyClient.createCredential(options) },
            encodeResponse = { response -> jsonCodec.encodeRegistrationResponse(response) },
            encodeErrorMessage = "Failed to encode registration response JSON",
        )
    }

    override suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = ::decodeAssertionOptions,
            execute = { options -> passkeyClient.getAssertion(options) },
            encodeResponse = { response -> jsonCodec.encodeAuthenticationResponse(response) },
            encodeErrorMessage = "Failed to encode authentication response JSON",
        )
    }

    private suspend fun <TOptions, TResponse> runJsonCeremony(
        requestJson: String,
        decodeOptions: (String) -> TOptions,
        execute: suspend (TOptions) -> PasskeyResult<TResponse>,
        encodeResponse: (TResponse) -> String,
        encodeErrorMessage: String,
    ): PasskeyResult<String> {
        val options = try {
            decodeOptions(requestJson)
        } catch (error: Throwable) {
            return PasskeyResult.Failure(
                PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"),
            )
        }

        return when (val result = execute(options)) {
            is PasskeyResult.Success -> {
                runCatching { encodeResponse(result.value) }
                    .fold(
                        onSuccess = { PasskeyResult.Success(it) },
                        onFailure = { error ->
                            PasskeyResult.Failure(
                                PasskeyClientError.Platform(
                                    "$encodeErrorMessage: ${error.message ?: "unknown error"}",
                                    error,
                                ),
                            )
                        },
                    )
            }

            is PasskeyResult.Failure -> result
        }
    }

    private fun decodeCreationOptions(payload: String): PublicKeyCredentialCreationOptions {
        return jsonCodec.decodeCreationOptionsOrThrowInvalid(payload)
    }

    private fun decodeAssertionOptions(payload: String): PublicKeyCredentialRequestOptions {
        return jsonCodec.decodeAssertionOptionsOrThrowInvalid(payload)
    }
}

public fun PasskeyClient.withJsonSupport(codec: PasskeyJsonCodec = KotlinxPasskeyJsonCodec()): JsonPasskeyClient {
    return DefaultJsonPasskeyClient(this, codec)
}

public fun PasskeyJsonCodec.encodeCreationOptionsOrThrowInvalid(options: PublicKeyCredentialCreationOptions): String {
    return fromCodecInvalidOptions("Failed to encode registration options JSON") {
        encodeCreationOptions(options)
    }
}

public fun PasskeyJsonCodec.encodeAssertionOptionsOrThrowInvalid(options: PublicKeyCredentialRequestOptions): String {
    return fromCodecInvalidOptions("Failed to encode authentication options JSON") {
        encodeAssertionOptions(options)
    }
}

public fun PasskeyJsonCodec.decodeCreationOptionsOrThrowInvalid(payload: String): PublicKeyCredentialCreationOptions {
    val validation = fromCodecInvalidOptions("Failed to parse registration options JSON") {
        decodeCreationOptions(payload)
    }
    return validation.toValueOrThrowInvalidOptions()
}

public fun PasskeyJsonCodec.decodeAssertionOptionsOrThrowInvalid(payload: String): PublicKeyCredentialRequestOptions {
    val validation = fromCodecInvalidOptions("Failed to parse authentication options JSON") {
        decodeAssertionOptions(payload)
    }
    return validation.toValueOrThrowInvalidOptions()
}

public fun PasskeyJsonCodec.decodeRegistrationResponseOrThrowPlatform(payload: String): RegistrationResponse {
    val validation = fromCodecPlatformResponse("Failed to parse registration response JSON") {
        decodeRegistrationResponse(payload)
    }
    return validation.toValueOrThrowPlatformResponse()
}

public fun PasskeyJsonCodec.decodeAuthenticationResponseOrThrowPlatform(payload: String): AuthenticationResponse {
    val validation = fromCodecPlatformResponse("Failed to parse authentication response JSON") {
        decodeAuthenticationResponse(payload)
    }
    return validation.toValueOrThrowPlatformResponse()
}

private inline fun <T> fromCodecInvalidOptions(message: String, block: () -> T): T {
    return runCatching(block)
        .getOrElse { error ->
            throw IllegalArgumentException("$message: ${error.message ?: "unknown error"}", error)
        }
}

private inline fun <T> fromCodecPlatformResponse(message: String, block: () -> T): T {
    return runCatching(block)
        .getOrElse { error ->
            throw IllegalStateException("$message: ${error.message ?: "unknown error"}", error)
        }
}

private fun <T> ValidationResult<T>.toValueOrThrowInvalidOptions(): T {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> throw IllegalArgumentException(firstValidationErrorMessage())
    }
}

private fun <T> ValidationResult<T>.toValueOrThrowPlatformResponse(): T {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> throw IllegalStateException(firstValidationErrorMessage())
    }
}

private fun ValidationResult.Invalid.firstValidationErrorMessage(): String {
    val firstError = errors.firstOrNull() ?: return "Unknown validation error"
    return "${firstError.field}: ${firstError.message}"
}

public class KotlinxPasskeyJsonCodec(
    private val requestJson: Json = Json { encodeDefaults = false },
    private val responseJson: Json = Json { ignoreUnknownKeys = true },
) : PasskeyJsonCodec {
    override fun encodeCreationOptions(options: PublicKeyCredentialCreationOptions): String {
        return requestJson.encodeToString(
            PublicKeyCredentialCreationOptionsDto.serializer(),
            WebAuthnDtoMapper.fromModel(options),
        )
    }

    override fun decodeCreationOptions(payload: String): ValidationResult<PublicKeyCredentialCreationOptions> {
        val dto = requestJson.decodeFromString(PublicKeyCredentialCreationOptionsDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }

    override fun encodeAssertionOptions(options: PublicKeyCredentialRequestOptions): String {
        return requestJson.encodeToString(
            PublicKeyCredentialRequestOptionsDto.serializer(),
            WebAuthnDtoMapper.fromModel(options),
        )
    }

    override fun decodeAssertionOptions(payload: String): ValidationResult<PublicKeyCredentialRequestOptions> {
        val dto = requestJson.decodeFromString(PublicKeyCredentialRequestOptionsDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }

    override fun encodeRegistrationResponse(response: RegistrationResponse): String {
        return responseJson.encodeToString(
            RegistrationResponseDto.serializer(),
            WebAuthnDtoMapper.fromModel(response),
        )
    }

    override fun decodeRegistrationResponse(payload: String): ValidationResult<RegistrationResponse> {
        val dto = responseJson.decodeFromString(RegistrationResponseDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }

    override fun encodeAuthenticationResponse(response: AuthenticationResponse): String {
        return responseJson.encodeToString(
            AuthenticationResponseDto.serializer(),
            WebAuthnDtoMapper.fromModel(response),
        )
    }

    override fun decodeAuthenticationResponse(payload: String): ValidationResult<AuthenticationResponse> {
        val dto = responseJson.decodeFromString(AuthenticationResponseDto.serializer(), payload)
        return WebAuthnDtoMapper.toModel(dto)
    }
}
