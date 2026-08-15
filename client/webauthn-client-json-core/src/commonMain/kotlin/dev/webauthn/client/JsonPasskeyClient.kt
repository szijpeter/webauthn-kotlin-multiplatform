@file:kotlin.jvm.JvmMultifileClass
@file:kotlin.jvm.JvmName("JsonPasskeyClientKt")
@file:Suppress("UndocumentedPublicFunction")

package dev.webauthn.client

import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

/** JSON-first facade over [PasskeyClient] for backend contracts that speak JSON DTOs. */
public interface JsonPasskeyClient {
    public suspend fun createCredentialJson(requestJson: String): PasskeyResult<String>

    public suspend fun getAssertionJson(requestJson: String): PasskeyResult<String>
}

/** Default JSON facade that maps request/response DTO payloads to model-level ceremonies. */
public class DefaultJsonPasskeyClient(
    private val passkeyClient: PasskeyClient,
    private val codec: WebAuthnJsonCodec = KotlinxWebAuthnJsonCodec(),
) : JsonPasskeyClient {
    override suspend fun createCredentialJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = { payload ->
                codec.decodeCreationOptions(payload).toValueOrThrow(::IllegalArgumentException)
            },
            execute = passkeyClient::createCredential,
            encodeResponse = { response -> codec.encodeRegistrationResponse(response.toRaw()) },
            encodeErrorMessage = "Failed to encode registration response JSON",
        )
    }

    override suspend fun getAssertionJson(requestJson: String): PasskeyResult<String> {
        return runJsonCeremony(
            requestJson = requestJson,
            decodeOptions = { payload ->
                codec.decodeRequestOptions(payload).toValueOrThrow(::IllegalArgumentException)
            },
            execute = passkeyClient::getAssertion,
            encodeResponse = { response -> codec.encodeAuthenticationResponse(response.toRaw()) },
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
        } catch (error: IllegalArgumentException) {
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
    codec: WebAuthnJsonCodec = KotlinxWebAuthnJsonCodec(),
): JsonPasskeyClient {
    return DefaultJsonPasskeyClient(this, codec)
}

private fun RegistrationResponse.toRaw(): RawRegistrationResponse = RawRegistrationResponse(
    credentialId = credentialId,
    clientDataJson = clientDataJson,
    attestationObject = attestationObject,
    authenticatorAttachment = authenticatorAttachment,
    extensions = extensions,
)

private fun AuthenticationResponse.toRaw(): RawAuthenticationResponse = RawAuthenticationResponse(
    credentialId = credentialId,
    clientDataJson = clientDataJson,
    authenticatorData = rawAuthenticatorData,
    signature = signature,
    userHandle = userHandle,
    authenticatorAttachment = authenticatorAttachment,
    extensions = extensions,
)
