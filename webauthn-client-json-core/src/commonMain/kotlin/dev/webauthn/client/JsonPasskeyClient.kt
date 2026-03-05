package dev.webauthn.client

import at.asitplus.KmmResult
import at.asitplus.catching
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
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

public interface PasskeyJsonMapper {
    public fun <T> encode(
        value: T,
        serializer: SerializationStrategy<T>,
    ): String

    public fun <T> decode(
        payload: String,
        deserializer: DeserializationStrategy<T>,
    ): T
}

public interface JsonPasskeyClient {
    public suspend fun createCredentialJson(requestJson: String): PasskeyResult<String>

    public suspend fun getAssertionJson(requestJson: String): PasskeyResult<String>
}

public class DefaultJsonPasskeyClient(
    private val passkeyClient: PasskeyClient,
    private val jsonMapper: PasskeyJsonMapper = KotlinxPasskeyJsonMapper(),
) : JsonPasskeyClient {
    override suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = { payload -> jsonMapper.decodeCreationOptionsOrThrowInvalid(payload) },
            execute = { options -> passkeyClient.createCredential(options) },
            encodeResponse = { response -> jsonMapper.encodeRegistrationResponse(response) },
            encodeErrorMessage = "Failed to encode registration response JSON",
        )
    }

    override suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = { payload -> jsonMapper.decodeAssertionOptionsOrThrowInvalid(payload) },
            execute = { options -> passkeyClient.getAssertion(options) },
            encodeResponse = { response -> jsonMapper.encodeAuthenticationResponse(response) },
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
        val options = catching { decodeOptions(requestJson) }
            .getOrElse { error ->
                return PasskeyResult.Failure(
                    PasskeyClientError.InvalidOptions(error.message ?: "Invalid options"),
                )
            }

        return when (val result = execute(options)) {
            is PasskeyResult.Success -> KmmResult(result.value)
                .mapCatching(encodeResponse)
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

            is PasskeyResult.Failure -> result
        }
    }
}

public fun PasskeyClient.withJsonSupport(
    mapper: PasskeyJsonMapper = KotlinxPasskeyJsonMapper(),
): JsonPasskeyClient {
    return DefaultJsonPasskeyClient(this, mapper)
}

@OptIn(ExperimentalSerializationApi::class)
public inline fun <reified T> T.serializeToJson(
    mapper: PasskeyJsonMapper,
    serializer: SerializationStrategy<T> = serializer(),
): String {
    return mapper.encode(this, serializer)
}

@OptIn(ExperimentalSerializationApi::class)
public inline fun <reified T> String.deserializeFromJson(
    mapper: PasskeyJsonMapper,
    deserializer: DeserializationStrategy<T> = serializer(),
): T {
    return mapper.decode(this, deserializer)
}

public fun PasskeyJsonMapper.encodeCreationOptionsOrThrowInvalid(options: PublicKeyCredentialCreationOptions): String {
    return fromMapperInvalidOptions("Failed to encode registration options JSON") {
        val dto = WebAuthnDtoMapper.fromModel(options)
        encode(dto, PublicKeyCredentialCreationOptionsDto.serializer())
    }
}

public fun PasskeyJsonMapper.encodeAssertionOptionsOrThrowInvalid(options: PublicKeyCredentialRequestOptions): String {
    return fromMapperInvalidOptions("Failed to encode authentication options JSON") {
        val dto = WebAuthnDtoMapper.fromModel(options)
        encode(dto, PublicKeyCredentialRequestOptionsDto.serializer())
    }
}

public fun PasskeyJsonMapper.decodeCreationOptionsOrThrowInvalid(payload: String): PublicKeyCredentialCreationOptions {
    val validation = fromMapperInvalidOptions("Failed to parse registration options JSON") {
        val dto = decode(payload, PublicKeyCredentialCreationOptionsDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalArgumentException(message) }
}

public fun PasskeyJsonMapper.decodeAssertionOptionsOrThrowInvalid(payload: String): PublicKeyCredentialRequestOptions {
    val validation = fromMapperInvalidOptions("Failed to parse authentication options JSON") {
        val dto = decode(payload, PublicKeyCredentialRequestOptionsDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalArgumentException(message) }
}

public fun PasskeyJsonMapper.encodeRegistrationResponse(response: RegistrationResponse): String {
    return fromMapperPlatformResponse("Failed to encode registration response JSON") {
        val dto = WebAuthnDtoMapper.fromModel(response)
        encode(dto, RegistrationResponseDto.serializer())
    }
}

public fun PasskeyJsonMapper.decodeRegistrationResponseOrThrowPlatform(payload: String): RegistrationResponse {
    val validation = fromMapperPlatformResponse("Failed to parse registration response JSON") {
        val dto = decode(payload, RegistrationResponseDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalStateException(message) }
}

public fun PasskeyJsonMapper.encodeAuthenticationResponse(response: AuthenticationResponse): String {
    return fromMapperPlatformResponse("Failed to encode authentication response JSON") {
        val dto = WebAuthnDtoMapper.fromModel(response)
        encode(dto, AuthenticationResponseDto.serializer())
    }
}

public fun PasskeyJsonMapper.decodeAuthenticationResponseOrThrowPlatform(payload: String): AuthenticationResponse {
    val validation = fromMapperPlatformResponse("Failed to parse authentication response JSON") {
        val dto = decode(payload, AuthenticationResponseDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalStateException(message) }
}

private inline fun <T> fromMapperInvalidOptions(message: String, block: () -> T): T =
    fromMapper(message, block) { composedMessage, error -> IllegalArgumentException(composedMessage, error) }

private inline fun <T> fromMapperPlatformResponse(message: String, block: () -> T): T =
    fromMapper(message, block) { composedMessage, error -> IllegalStateException(composedMessage, error) }

private inline fun <T, TThrowable : Throwable> fromMapper(
    message: String,
    block: () -> T,
    throwableFactory: (String, Throwable) -> TThrowable,
): T {
    return catching(block)
        .getOrElse { error ->
            val composedMessage = "$message: ${error.message ?: "unknown error"}"
            throw throwableFactory(composedMessage, error)
        }
}

private fun <T, TThrowable : Throwable> ValidationResult<T>.toValueOrThrow(
    throwableFactory: (String) -> TThrowable,
): T {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> throw throwableFactory(firstValidationErrorMessage())
    }
}

private fun ValidationResult.Invalid.firstValidationErrorMessage(): String {
    val firstError = errors.firstOrNull() ?: return "Unknown validation error"
    return "${firstError.field}: ${firstError.message}"
}

public class KotlinxPasskeyJsonMapper(
    private val json: Json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    },
) : PasskeyJsonMapper {
    override fun <T> encode(
        value: T,
        serializer: SerializationStrategy<T>,
    ): String {
        return json.encodeToString(serializer, value)
    }

    override fun <T> decode(
        payload: String,
        deserializer: DeserializationStrategy<T>,
    ): T {
        return json.decodeFromString(deserializer, payload)
    }
}
