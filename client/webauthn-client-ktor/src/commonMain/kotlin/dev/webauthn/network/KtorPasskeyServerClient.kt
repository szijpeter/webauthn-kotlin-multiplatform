package dev.webauthn.network

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Route configuration for [KtorPasskeyServerClient]. */
public data class KtorPasskeyRoutes(
    public val registerOptionsPath: String = "/webauthn/registration/start",
    public val registerFinishPath: String = "/webauthn/registration/finish",
    public val signInOptionsPath: String = "/webauthn/authentication/start",
    public val signInFinishPath: String = "/webauthn/authentication/finish",
)

/** Ktor-based [PasskeyServerClient] implementation for JSON WebAuthn backend endpoints. */
public class KtorPasskeyServerClient(
    private val httpClient: HttpClient,
    endpointBase: String,
    private val routes: KtorPasskeyRoutes = KtorPasskeyRoutes(),
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    private val endpointBase: String = endpointBase.trimEnd('/')

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        return postForOptions(
            path = routes.registerOptionsPath,
            params = params,
            operation = "Registration start",
            decode = ::decodeRegistrationOptions,
        )
    }

    @Suppress("UnusedParameter")
    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        return postForFinish(
            path = routes.registerFinishPath,
            payload = RegistrationFinishPayload(
                response = WebAuthnDtoMapper.fromModel(response),
            ),
            operation = "Registration finish",
        )
    }

    override suspend fun getSignInOptions(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        return postForOptions(
            path = routes.signInOptionsPath,
            params = params,
            operation = "Authentication start",
            decode = ::decodeAuthenticationOptions,
        )
    }

    @Suppress("UnusedParameter")
    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        return postForFinish(
            path = routes.signInFinishPath,
            payload = AuthenticationFinishPayload(
                response = WebAuthnDtoMapper.fromModel(response),
            ),
            operation = "Authentication finish",
        )
    }

    /**
     * Adapts this transport to the opaque-state [RegistrationBackend] flow API.
     *
     * This default HTTP contract needs no client-side finish state; signed response data remains
     * the server authority.
     */
    public fun registrationBackend(): RegistrationBackend<RegistrationStartPayload, Unit, PasskeyFinishResult> {
        return object : RegistrationBackend<RegistrationStartPayload, Unit, PasskeyFinishResult> {
            override suspend fun start(
                input: RegistrationStartPayload,
            ): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> {
                return CeremonyStart(state = Unit, options = getRegisterOptions(input).toFlowValue())
            }

            @Suppress("UnusedParameter")
            override suspend fun finish(
                state: Unit,
                response: RegistrationResponse,
            ): PasskeyFinishResult {
                return postForFinish(
                    path = routes.registerFinishPath,
                    payload = RegistrationFinishPayload(response = WebAuthnDtoMapper.fromModel(response)),
                    operation = "Registration finish",
                )
            }
        }
    }

    /** Adapts this transport to the opaque-state [AuthenticationBackend] flow API. */
    public fun authenticationBackend(): AuthenticationBackend<AuthenticationStartPayload, Unit, PasskeyFinishResult> {
        return object : AuthenticationBackend<AuthenticationStartPayload, Unit, PasskeyFinishResult> {
            override suspend fun start(
                input: AuthenticationStartPayload,
            ): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> {
                return CeremonyStart(state = Unit, options = getSignInOptions(input).toFlowValue())
            }

            @Suppress("UnusedParameter")
            override suspend fun finish(
                state: Unit,
                response: AuthenticationResponse,
            ): PasskeyFinishResult {
                return postForFinish(
                    path = routes.signInFinishPath,
                    payload = AuthenticationFinishPayload(response = WebAuthnDtoMapper.fromModel(response)),
                    operation = "Authentication finish",
                )
            }
        }
    }

    private fun endpointFor(path: String): String {
        val normalizedPath = if (path.startsWith("/")) path else "/$path"
        return "$endpointBase$normalizedPath"
    }

    private suspend fun <TResult> postForOptions(
        path: String,
        params: Any,
        operation: String,
        decode: (String, String) -> ValidationResult<TResult>,
    ): ValidationResult<TResult> {
        val response = httpClient.post(endpointFor(path)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(params)
        }
        val responseText = response.bodyAsText()
        throwIfHttpError(response, responseText, operation)
        return decode(responseText, "$operation response")
    }

    private suspend fun postForFinish(
        path: String,
        payload: Any,
        operation: String,
    ): PasskeyFinishResult {
        val response = httpClient.post(endpointFor(path)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(payload)
        }
        val responseText = response.bodyAsText()
        throwIfHttpError(response, responseText, operation)
        return decodeFinishResponse(responseText, "$operation response") { status ->
            "$operation was rejected by the server with status '$status'."
        }
    }
}

private fun decodeRegistrationOptions(
    body: String,
    operation: String,
): ValidationResult<PublicKeyCredentialCreationOptions> {
    val dto = decodeOrThrow<PublicKeyCredentialCreationOptionsDto>(body, operation)
    return WebAuthnDtoMapper.toModel(dto)
}

private fun <T> ValidationResult<T>.toFlowValue(): T = when (this) {
    is ValidationResult.Valid -> value
    is ValidationResult.Invalid -> throw IllegalArgumentException(errors.joinToString("; ") { it.message })
}

private fun decodeAuthenticationOptions(
    body: String,
    operation: String,
): ValidationResult<PublicKeyCredentialRequestOptions> {
    val dto = decodeOrThrow<PublicKeyCredentialRequestOptionsDto>(body, operation)
    return WebAuthnDtoMapper.toModel(dto)
}

private fun decodeFinishResponse(
    body: String,
    operation: String,
    rejectedMessage: (String) -> String,
): PasskeyFinishResult {
    val result = decodeOrThrow<FinishPayloadResponse>(body, operation)
    return if (result.status == "ok") {
        PasskeyFinishResult.Verified
    } else {
        PasskeyFinishResult.Rejected(rejectedMessage(result.status))
    }
}

/** Payload for registration-start endpoint requests. */
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
) {
    override fun toString(): String {
        val extensionsValue = if (extensions == null) "none" else "present"
        val residentKeyValue = residentKey ?: "null"
        return "RegistrationStartPayload(" +
            "rpId=$rpId, rpName=$rpName, origin=$origin, " +
            "userName=<redacted>, userDisplayName=<redacted>, userHandle=<redacted>, " +
            "residentKey=$residentKeyValue, extensions=$extensionsValue)"
    }
}

/** Payload for authentication-start endpoint requests. */
@Serializable
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String? = null,
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
) {
    override fun toString(): String {
        val userNameValue = if (userName == null) "null" else "<redacted>"
        val extensionsValue = if (extensions == null) "none" else "present"
        return "AuthenticationStartPayload(" +
            "rpId=$rpId, origin=$origin, userName=$userNameValue, " +
            "extensions=$extensionsValue)"
    }
}

@Serializable
private data class RegistrationFinishPayload(
    val response: RegistrationResponseDto,
)

@Serializable
private data class AuthenticationFinishPayload(
    val response: AuthenticationResponseDto,
)

@Serializable
private data class FinishPayloadResponse(
    val status: String,
)

@Serializable
private data class ServerErrorPayload(
    val errors: List<String>? = null,
)

private val contractJson: Json = Json {
    ignoreUnknownKeys = true
}

private fun throwIfHttpError(
    response: HttpResponse,
    responseText: String,
    operation: String,
) {
    if (response.status.isSuccess()) {
        return
    }
    val details = serverErrorMessage(responseText)
    error("$operation failed with HTTP ${response.status.value}: $details")
}

private inline fun <reified T> decodeOrThrow(
    body: String,
    operation: String,
): T {
    return runCatching { contractJson.decodeFromString<T>(body) }
        .getOrElse { error ->
            throw IllegalStateException(
                "$operation could not be parsed: ${error.message}. Body length=${body.length}",
            )
        }
}

private fun serverErrorMessage(body: String): String {
    val trimmed = body.trim()
    if (trimmed.isEmpty()) {
        return "<empty>"
    }
    val fromErrors = runCatching {
        contractJson.decodeFromString<ServerErrorPayload>(trimmed)
            .errors
            ?.filter(String::isNotBlank)
            ?.joinToString("; ")
    }.getOrNull()
        ?.takeIf(String::isNotBlank)
    return fromErrors ?: "<redacted non-empty body length=${trimmed.length}>"
}
