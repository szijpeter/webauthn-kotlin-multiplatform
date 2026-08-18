package dev.webauthn.network.kotlinx

import dev.webauthn.client.CeremonyStart
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.KtorPasskeyContractCodec
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Kotlinx Serialization codec for the default `/webauthn/...` contract. */
public class KotlinxKtorPasskeyContractCodec :
    KtorPasskeyContractCodec<
        RegistrationStartPayload,
        Unit,
        DefaultPasskeyFinishResult,
        AuthenticationStartPayload,
        Unit,
        DefaultPasskeyFinishResult,
    > {
    override fun encodeRegistrationStart(input: RegistrationStartPayload): String = json.encodeToString(input)

    override fun decodeRegistrationStart(
        body: String,
    ): ValidationResult<CeremonyStart<Unit, PublicKeyCredentialCreationOptions>> =
        WebAuthnDtoMapper.toModel(decodeOrThrow<PublicKeyCredentialCreationOptionsDto>(body, "Registration start"))
            .let { result ->
                when (result) {
                    is ValidationResult.Valid -> ValidationResult.Valid(CeremonyStart(Unit, result.value))
                    is ValidationResult.Invalid -> result
                }
            }

    override fun encodeRegistrationFinish(state: Unit, response: RawRegistrationResponse): String =
        json.encodeToString(RegistrationFinishPayload(WebAuthnDtoMapper.fromModel(response)))

    override fun decodeRegistrationFinish(body: String): DefaultPasskeyFinishResult =
        decodeFinish(body, "Registration finish")

    override fun encodeAuthenticationStart(input: AuthenticationStartPayload): String = json.encodeToString(input)

    override fun decodeAuthenticationStart(
        body: String,
    ): ValidationResult<CeremonyStart<Unit, PublicKeyCredentialRequestOptions>> =
        WebAuthnDtoMapper.toModel(
            decodeOrThrow<PublicKeyCredentialRequestOptionsDto>(body, "Authentication start"),
        )
            .let { result ->
                when (result) {
                    is ValidationResult.Valid -> ValidationResult.Valid(CeremonyStart(Unit, result.value))
                    is ValidationResult.Invalid -> result
                }
            }

    override fun encodeAuthenticationFinish(state: Unit, response: RawAuthenticationResponse): String =
        json.encodeToString(AuthenticationFinishPayload(WebAuthnDtoMapper.fromModel(response)))

    override fun decodeAuthenticationFinish(body: String): DefaultPasskeyFinishResult =
        decodeFinish(body, "Authentication finish")

    override fun decodeError(body: String): String? = runCatching {
        json.decodeFromString<ServerErrorPayload>(body).errors
            ?.filter(String::isNotBlank)
            ?.joinToString(";")
            ?.takeIf(String::isNotBlank)
    }.getOrNull()

    private fun decodeFinish(body: String, operation: String): DefaultPasskeyFinishResult {
        val result = decodeOrThrow<FinishPayloadResponse>(body, operation)
        return if (result.status == "ok") {
            DefaultPasskeyFinishResult.Verified
        } else {
            DefaultPasskeyFinishResult.Rejected("$operation was rejected by the server with status '${result.status}'.")
        }
    }

    private inline fun <reified T> decodeOrThrow(body: String, operation: String): T =
        runCatching { json.decodeFromString<T>(body) }.getOrElse { error ->
            throw IllegalStateException("$operation could not be parsed: ${error.message}. Body length=${body.length}")
        }
}

/** Default start payload for the registration endpoint. */
@Serializable
public data class RegistrationStartPayload(
    public val rpId: String,
    public val rpName: String,
    public val origin: String,
    public val userName: String,
    public val userDisplayName: String,
    public val userHandle: String,
    public val residentKey: String? = null,
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

/** Default start payload for the authentication endpoint. */
@Serializable
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String? = null,
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

/** Outcome of the default `/webauthn/...` finish response contract. */
public sealed interface DefaultPasskeyFinishResult {
    /** The backend accepted and verified the ceremony response. */
    public data object Verified : DefaultPasskeyFinishResult
    public data class Rejected(public val message: String? = null) : DefaultPasskeyFinishResult
}

@Serializable
private data class RegistrationFinishPayload(val response: RegistrationResponseDto)

@Serializable
private data class AuthenticationFinishPayload(val response: AuthenticationResponseDto)

@Serializable
private data class FinishPayloadResponse(val status: String)

@Serializable
private data class ServerErrorPayload(val errors: List<String>? = null)

private val json = Json { ignoreUnknownKeys = true }
