@file:kotlin.jvm.JvmMultifileClass
@file:kotlin.jvm.JvmName("JsonPasskeyClientKt")
@file:Suppress("UndocumentedPublicFunction")

package dev.webauthn.client

import at.asitplus.catching

/** JSON codec abstraction used by the JSON client facade. */
public interface PasskeyJsonMapper {
    public fun <T> encode(
        value: T,
        serializer: kotlinx.serialization.SerializationStrategy<T>,
    ): String

    public fun <T> decode(
        payload: String,
        deserializer: kotlinx.serialization.DeserializationStrategy<T>,
    ): T
}

/** JSON-first facade over [PasskeyClient] for backend contracts that speak JSON DTOs. */
public interface JsonPasskeyClient {
    public suspend fun createCredentialJson(requestJson: String): PasskeyResult<String>

    public suspend fun getAssertionJson(requestJson: String): PasskeyResult<String>
}

/** Default JSON facade that maps request/response DTO payloads to model-level ceremonies. */
public class DefaultJsonPasskeyClient(
    private val passkeyClient: PasskeyClient,
    private val jsonMapper: PasskeyJsonMapper = KotlinxPasskeyJsonMapper(),
) : JsonPasskeyClient {
    override suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = jsonMapper::decodeCreationOptionsOrThrowInvalid,
            execute = passkeyClient::createCredential,
            encodeResponse = jsonMapper::encodeRegistrationResponse,
            encodeErrorMessage = "Failed to encode registration response JSON",
        )
    }

    override suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = jsonMapper::decodeAssertionOptionsOrThrowInvalid,
            execute = passkeyClient::getAssertion,
            encodeResponse = jsonMapper::encodeAuthenticationResponse,
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
            is PasskeyResult.Success -> runCatching {
                encodeResponse(result.value)
            }.fold(
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
