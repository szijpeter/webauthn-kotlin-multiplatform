package dev.webauthn.network

import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import kotlinx.serialization.Serializable

public class WebAuthnKtorClient(
    private val httpClient: HttpClient,
    private val endpointBase: String,
) {
    public suspend fun startRegistration(request: RegistrationStartPayload): ValidationResult<PublicKeyCredentialCreationOptions> {
        val dto: PublicKeyCredentialCreationOptionsDto =
            httpClient.post("$endpointBase/webauthn/registration/start") {
                setBody(request)
            }.body()

        return WebAuthnDtoMapper.toModel(dto)
    }

    public suspend fun finishRegistration(request: RegistrationFinishPayload): Boolean {
        val response: FinishPayloadResponse =
            httpClient.post("$endpointBase/webauthn/registration/finish") {
                setBody(request)
            }.body()

        return response.status == "ok"
    }

    public suspend fun startAuthentication(request: AuthenticationStartPayload): ValidationResult<PublicKeyCredentialRequestOptions> {
        val dto: PublicKeyCredentialRequestOptionsDto =
            httpClient.post("$endpointBase/webauthn/authentication/start") {
                setBody(request)
            }.body()

        return WebAuthnDtoMapper.toModel(dto)
    }

    public suspend fun finishAuthentication(request: AuthenticationFinishPayload): Boolean {
        val response: FinishPayloadResponse =
            httpClient.post("$endpointBase/webauthn/authentication/finish") {
                setBody(request)
            }.body()

        return response.status == "ok"
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
)

@Serializable
public data class RegistrationFinishPayload(
    public val response: RegistrationResponseDto,
    public val clientDataType: String,
    public val challenge: String,
    public val origin: String,
)

@Serializable
public data class AuthenticationFinishPayload(
    public val response: AuthenticationResponseDto,
    public val clientDataType: String,
    public val challenge: String,
    public val origin: String,
)

@Serializable
public data class FinishPayloadResponse(
    public val status: String,
)

public fun CollectedClientData.toRegistrationFinishPayload(response: RegistrationResponseDto): RegistrationFinishPayload {
    return RegistrationFinishPayload(
        response = response,
        clientDataType = type,
        challenge = challenge.value.encoded(),
        origin = origin.value,
    )
}

public fun CollectedClientData.toAuthenticationFinishPayload(response: AuthenticationResponseDto): AuthenticationFinishPayload {
    return AuthenticationFinishPayload(
        response = response,
        clientDataType = type,
        challenge = challenge.value.encoded(),
        origin = origin.value,
    )
}
