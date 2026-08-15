package dev.webauthn.network.kotlinx

import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.KtorPasskeyContractCodec
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Kotlinx Serialization codec for the default `/webauthn/…` Ktor backend contract. */
public class KotlinxKtorPasskeyContractCodec :
    KtorPasskeyContractCodec<
        RegistrationStartPayload,
        AuthenticationStartPayload,
        PasskeyFinishResult,
        PasskeyFinishResult,
    > {
    override fun encodeRegistrationStart(input: RegistrationStartPayload): String = json.encodeToString(input)

    override fun decodeRegistrationStart(value: String): ValidationResult<PublicKeyCredentialCreationOptions> =
        WebAuthnDtoMapper.toModel(
            decodeOrThrow<PublicKeyCredentialCreationOptionsDto>(value, "Registration start response"),
        )

    override fun encodeRegistrationFinish(response: RawRegistrationResponse): String =
        json.encodeToString(RegistrationFinishPayload(WebAuthnDtoMapper.fromModel(response)))

    override fun decodeRegistrationFinish(value: String): PasskeyFinishResult =
        decodeFinish(value, "Registration finish")

    override fun encodeAuthenticationStart(input: AuthenticationStartPayload): String = json.encodeToString(input)

    override fun decodeAuthenticationStart(value: String): ValidationResult<PublicKeyCredentialRequestOptions> =
        WebAuthnDtoMapper.toModel(
            decodeOrThrow<PublicKeyCredentialRequestOptionsDto>(value, "Authentication start response"),
        )

    override fun encodeAuthenticationFinish(response: RawAuthenticationResponse): String =
        json.encodeToString(AuthenticationFinishPayload(WebAuthnDtoMapper.fromModel(response)))

    override fun decodeAuthenticationFinish(value: String): PasskeyFinishResult =
        decodeFinish(value, "Authentication finish")

    override fun decodeError(value: String): String? = runCatching {
        json.decodeFromString<ServerErrorPayload>(value)
            .errors
            ?.filter(String::isNotBlank)
            ?.joinToString("; ")
            ?.takeIf(String::isNotBlank)
    }.getOrNull()

    private fun decodeFinish(value: String, operation: String): PasskeyFinishResult {
        val result = decodeOrThrow<FinishPayloadResponse>(value, "$operation response")
        return if (result.status == "ok") PasskeyFinishResult.Verified
        else PasskeyFinishResult.Rejected("$operation was rejected by the server with status '${result.status}'.")
    }

    private inline fun <reified T> decodeOrThrow(value: String, operation: String): T =
        runCatching { json.decodeFromString<T>(value) }
            .getOrElse { error ->
                throw IllegalStateException(
                    "$operation could not be parsed: ${error.message}. Body length=${value.length}",
                )
            }
}

@Serializable
private data class RegistrationFinishPayload(val response: RegistrationResponseDto)

@Serializable
private data class AuthenticationFinishPayload(val response: AuthenticationResponseDto)

@Serializable
private data class FinishPayloadResponse(val status: String)

@Serializable
private data class ServerErrorPayload(val errors: List<String>? = null)

private val json: Json = Json { ignoreUnknownKeys = true }
