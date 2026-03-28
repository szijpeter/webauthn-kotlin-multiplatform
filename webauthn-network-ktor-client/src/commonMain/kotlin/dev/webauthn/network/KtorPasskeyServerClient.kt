package dev.webauthn.network

import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
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

/** Backend API contract consumed by [KtorPasskeyServerClient]. */
public interface BackendContract {
    public suspend fun getRegisterOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions>

    public suspend fun finishRegister(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult

    public suspend fun getSignInOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions>

    public suspend fun finishSignIn(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult
}

/** Default backend contract matching the sample/server route structure. */
public class DefaultBackendContract(
    private val registerOptionsPath: String = "/webauthn/registration/start",
    private val registerVerifyPath: String = "/webauthn/registration/finish",
    private val authenticateOptionsPath: String = "/webauthn/authentication/start",
    private val authenticateVerifyPath: String = "/webauthn/authentication/finish",
) : BackendContract {
    override suspend fun getRegisterOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        val response = httpClient.post(endpointFor(registerOptionsPath)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(params)
        }
        val responseText = response.bodyAsText()
        throwIfHttpError(
            response = response,
            responseText = responseText,
            operation = "Registration start",
        )
        val dto = decodeOrThrow<PublicKeyCredentialCreationOptionsDto>(
            body = responseText,
            operation = "Registration start response",
        )

        return WebAuthnDtoMapper.toModel(dto)
    }

    override suspend fun finishRegister(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val finishPayload = RegistrationFinishPayload(
            response = responseDto,
            clientDataType = "webauthn.create",
            challenge = challengeAsBase64Url,
            origin = params.origin,
        )
        val httpResponse = httpClient.post(endpointFor(registerVerifyPath)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(finishPayload)
        }
        val responseText = httpResponse.bodyAsText()
        throwIfHttpError(
            response = httpResponse,
            responseText = responseText,
            operation = "Registration finish",
        )
        val result = decodeOrThrow<FinishPayloadResponse>(
            body = responseText,
            operation = "Registration finish response",
        )
        return if (result.status == "ok") {
            PasskeyFinishResult.Verified
        } else {
            PasskeyFinishResult.Rejected(
                "Registration verification was rejected by the server with status '${result.status}'.",
            )
        }
    }

    override suspend fun getSignInOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        val response = httpClient.post(endpointFor(authenticateOptionsPath)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(params)
        }
        val responseText = response.bodyAsText()
        throwIfHttpError(
            response = response,
            responseText = responseText,
            operation = "Authentication start",
        )
        val dto = decodeOrThrow<PublicKeyCredentialRequestOptionsDto>(
            body = responseText,
            operation = "Authentication start response",
        )

        return WebAuthnDtoMapper.toModel(dto)
    }

    override suspend fun finishSignIn(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val finishPayload = AuthenticationFinishPayload(
            response = responseDto,
            clientDataType = "webauthn.get",
            challenge = challengeAsBase64Url,
            origin = params.origin,
        )
        val httpResponse = httpClient.post(endpointFor(authenticateVerifyPath)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(finishPayload)
        }
        val responseText = httpResponse.bodyAsText()
        throwIfHttpError(
            response = httpResponse,
            responseText = responseText,
            operation = "Authentication finish",
        )
        val result = decodeOrThrow<FinishPayloadResponse>(
            body = responseText,
            operation = "Authentication finish response",
        )
        return if (result.status == "ok") {
            PasskeyFinishResult.Verified
        } else {
            PasskeyFinishResult.Rejected(
                "Authentication verification was rejected by the server with status '${result.status}'.",
            )
        }
    }
}

/** Ktor-based [PasskeyServerClient] implementation for JSON WebAuthn backend endpoints. */
public class KtorPasskeyServerClient(
    private val httpClient: HttpClient,
    endpointBase: String,
    private val backendContract: BackendContract = DefaultBackendContract(),
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    private val endpointBase: String = endpointBase.trimEnd('/')

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> = backendContract.getRegisterOptions(
        httpClient = httpClient,
        endpointFor = ::endpointFor,
        params = params,
    )

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = backendContract.finishRegister(
        httpClient = httpClient,
        endpointFor = ::endpointFor,
        params = params,
        response = response,
        challengeAsBase64Url = challengeAsBase64Url,
    )

    override suspend fun getSignInOptions(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> = backendContract.getSignInOptions(
        httpClient = httpClient,
        endpointFor = ::endpointFor,
        params = params,
    )

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult = backendContract.finishSignIn(
        httpClient = httpClient,
        endpointFor = ::endpointFor,
        params = params,
        response = response,
        challengeAsBase64Url = challengeAsBase64Url,
    )

    private fun endpointFor(path: String): String {
        val normalizedPath = if (path.startsWith("/")) path else "/$path"
        return "$endpointBase$normalizedPath"
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
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
) {
    override fun toString(): String {
        val extensionsValue = if (extensions == null) "none" else "present"
        return "RegistrationStartPayload(" +
            "rpId=$rpId, rpName=$rpName, origin=$origin, " +
            "userName=<redacted>, userDisplayName=<redacted>, userHandle=<redacted>, " +
            "extensions=$extensionsValue)"
    }
}

/** Payload for authentication-start endpoint requests. */
@Serializable
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String,
    public val userHandle: String? = null,
    public val extensions: AuthenticationExtensionsClientInputsDto? = null,
) {
    override fun toString(): String {
        val userHandleValue = if (userHandle == null) "null" else "<redacted>"
        val extensionsValue = if (extensions == null) "none" else "present"
        return "AuthenticationStartPayload(" +
            "rpId=$rpId, origin=$origin, userName=<redacted>, " +
            "userHandle=$userHandleValue, extensions=$extensionsValue)"
    }
}

@Serializable
private data class RegistrationFinishPayload(
    val response: RegistrationResponseDto,
    val clientDataType: String,
    val challenge: String,
    val origin: String,
)

@Serializable
private data class AuthenticationFinishPayload(
    val response: AuthenticationResponseDto,
    val clientDataType: String,
    val challenge: String,
    val origin: String,
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
            ?.filter { it.isNotBlank() }
            ?.joinToString("; ")
    }.getOrNull()?.takeIf { it.isNotBlank() }
    return fromErrors ?: "<redacted non-empty body length=${trimmed.length}>"
}
