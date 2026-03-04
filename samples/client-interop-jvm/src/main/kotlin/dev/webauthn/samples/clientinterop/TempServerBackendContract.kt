package dev.webauthn.samples.clientinterop

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.BackendContract
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.AuthenticationExtensionsClientOutputsDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.AuthenticatorSelectionCriteriaDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialDescriptorDto
import dev.webauthn.serialization.PublicKeyCredentialParametersDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.RpEntityDto
import dev.webauthn.serialization.UserEntityDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal class TempServerBackendContract : BackendContract {
    override suspend fun getRegisterOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        val response: TempServerRegistrationOptionsResponse =
            httpClient.post(endpointFor("/register/options")) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(
                    TempServerRegistrationOptionsRequest(
                        userId = params.userHandle,
                        userName = params.userName,
                    ),
                )
            }.body()

        val dto = PublicKeyCredentialCreationOptionsDto(
            rp = response.rp,
            user = response.user,
            challenge = response.challenge,
            pubKeyCredParams = response.pubKeyCredParams,
            timeoutMs = response.timeoutMs,
            excludeCredentials = response.excludeCredentials,
            authenticatorSelection = AuthenticatorSelectionCriteriaDto(
                authenticatorAttachment = response.authenticatorSelection?.authenticatorAttachment,
                residentKey = response.authenticatorSelection?.residentKey ?: "preferred",
                userVerification = response.authenticatorSelection?.userVerification ?: "preferred",
            ),
            attestation = response.attestation,
            extensions = response.extensions,
        )
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
        val payload = TempServerRegistrationVerifyRequest(
            id = responseDto.id,
            rawId = responseDto.rawId,
            type = "public-key",
            response = responseDto.response,
            clientExtensionResults = responseDto.clientExtensionResults,
        )

        return runCatching {
            val httpResponse = httpClient.post("${endpointFor("/register/verify")}?userId=${params.userHandle}") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(payload)
            }
            httpResponse.status.isSuccess() && httpResponse.body<TempServerVerificationResponse>().success
        }.getOrDefault(false)
    }

    override suspend fun getSignInOptions(
        httpClient: HttpClient,
        endpointFor: (String) -> String,
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        val stableUserId = params.userHandle ?: params.userName
        val response: TempServerAuthenticationOptionsResponse =
            httpClient.post(endpointFor("/authenticate/options")) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(TempServerAuthenticationOptionsRequest(userId = stableUserId))
            }.body()

        val dto = PublicKeyCredentialRequestOptionsDto(
            challenge = response.challenge,
            rpId = response.rpId,
            timeoutMs = response.timeoutMs,
            allowCredentials = response.allowCredentials,
            userVerification = response.userVerification,
            extensions = null,
        )

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
        val payload = TempServerAuthenticationVerifyRequest(
            id = responseDto.id,
            rawId = responseDto.rawId,
            type = "public-key",
            response = responseDto.response,
            clientExtensionResults = responseDto.clientExtensionResults,
        )

        return runCatching {
            val httpResponse = httpClient.post(
                "${endpointFor("/authenticate/verify")}?challenge=$challengeAsBase64Url",
            ) {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(payload)
            }
            httpResponse.status.isSuccess() && httpResponse.body<TempServerVerificationResponse>().success
        }.getOrDefault(false)
    }
}

@Serializable
private data class TempServerRegistrationOptionsRequest(
    val userId: String,
    val userName: String,
)

@Serializable
private data class TempServerAuthenticationOptionsRequest(
    val userId: String? = null,
)

@Serializable
private data class TempServerAuthenticatorSelectionDto(
    val authenticatorAttachment: String? = null,
    val residentKey: String = "preferred",
    val userVerification: String = "preferred",
)

@Serializable
private data class TempServerRegistrationOptionsResponse(
    val challenge: String,
    val rp: RpEntityDto,
    val user: UserEntityDto,
    val pubKeyCredParams: List<PublicKeyCredentialParametersDto>,
    @SerialName("timeout") val timeoutMs: Long? = null,
    val attestation: String? = null,
    val authenticatorSelection: TempServerAuthenticatorSelectionDto? = null,
    val excludeCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
private data class TempServerAuthenticationOptionsResponse(
    val challenge: String,
    val rpId: String,
    @SerialName("timeout") val timeoutMs: Long? = null,
    val userVerification: String = "preferred",
    val allowCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
)

@Serializable
private data class TempServerRegistrationVerifyRequest(
    val id: String,
    val rawId: String,
    val type: String,
    val response: RegistrationResponsePayloadDto,
    val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
)

@Serializable
private data class TempServerAuthenticationVerifyRequest(
    val id: String,
    val rawId: String,
    val type: String,
    val response: AuthenticationResponsePayloadDto,
    val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
)

@Serializable
private data class TempServerVerificationResponse(
    val success: Boolean,
    val message: String? = null,
)
