package dev.webauthn.network

import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import kotlinx.serialization.Serializable

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
    ): Boolean

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
    ): Boolean
}

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
        val dto: PublicKeyCredentialCreationOptionsDto =
            httpClient.post(endpointFor(registerOptionsPath)) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(params)
            }.body()

        return WebAuthnDtoMapper.toModel(dto)
    }

    override suspend fun finishRegister(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val finishPayload = RegistrationFinishPayload(
            response = responseDto,
            clientDataType = "webauthn.create",
            challenge = challengeAsBase64Url,
            origin = params.origin,
        )
        val result: FinishPayloadResponse =
            httpClient.post(endpointFor(registerVerifyPath)) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(finishPayload)
            }.body()
        return result.status == "ok"
    }

    override suspend fun getSignInOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        val dto: PublicKeyCredentialRequestOptionsDto =
            httpClient.post(endpointFor(authenticateOptionsPath)) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(params)
            }.body()

        return WebAuthnDtoMapper.toModel(dto)
    }

    override suspend fun finishSignIn(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val finishPayload = AuthenticationFinishPayload(
            response = responseDto,
            clientDataType = "webauthn.get",
            challenge = challengeAsBase64Url,
            origin = params.origin,
        )
        val result: FinishPayloadResponse =
            httpClient.post(endpointFor(authenticateVerifyPath)) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(finishPayload)
            }.body()
        return result.status == "ok"
    }
}

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
    ): Boolean = backendContract.finishRegister(
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
    ): Boolean = backendContract.finishSignIn(
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

@Serializable
public data class RegistrationStartPayload(
    public val rpId: String,
    public val rpName: String,
    public val origin: String,
    public val userName: String,
    public val userDisplayName: String,
    public val userHandle: String,
)

@Serializable
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String,
    public val userHandle: String? = null,
)

@Serializable
private data class RegistrationFinishPayload(
    val response: dev.webauthn.serialization.RegistrationResponseDto,
    val clientDataType: String,
    val challenge: String,
    val origin: String,
)

@Serializable
private data class AuthenticationFinishPayload(
    val response: dev.webauthn.serialization.AuthenticationResponseDto,
    val clientDataType: String,
    val challenge: String,
    val origin: String,
)

@Serializable
private data class FinishPayloadResponse(
    val status: String,
)
