package dev.webauthn.network

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialDescriptorDto
import dev.webauthn.serialization.PublicKeyCredentialParametersDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
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

public enum class WebAuthnBackendProfile {
    LIBRARY_ROUTES,
    PASSKEY_ENCRYPTION_POC,
}

public class WebAuthnInteropKtorClient(
    private val httpClient: HttpClient,
    private val endpointBase: String,
    private val profile: WebAuthnBackendProfile = WebAuthnBackendProfile.LIBRARY_ROUTES,
) {
    private val libraryClient = WebAuthnKtorClient(httpClient, endpointBase)
    private val registrationChallengeToContext: MutableMap<String, PendingPocRegistration> = mutableMapOf()
    private val registrationUserNameToUserId: MutableMap<String, String> = mutableMapOf()

    public suspend fun startRegistration(request: RegistrationStartPayload): ValidationResult<PublicKeyCredentialCreationOptions> {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> libraryClient.startRegistration(request)
            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> startRegistrationAgainstPoc(request)
        }
    }

    public suspend fun finishRegistration(request: RegistrationFinishPayload): Boolean {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> libraryClient.finishRegistration(request)
            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> finishRegistrationAgainstPoc(request)
        }
    }

    public suspend fun startAuthentication(request: AuthenticationStartPayload): ValidationResult<PublicKeyCredentialRequestOptions> {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> libraryClient.startAuthentication(request)
            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> startAuthenticationAgainstPoc(request)
        }
    }

    public suspend fun finishAuthentication(request: AuthenticationFinishPayload): Boolean {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> libraryClient.finishAuthentication(request)
            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> finishAuthenticationAgainstPoc(request)
        }
    }

    private suspend fun startRegistrationAgainstPoc(
        request: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        val response: PocRegistrationOptionsResponse =
            httpClient.post("$endpointBase/register/options") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(
                    PocRegistrationOptionsRequest(
                        userId = request.userHandle,
                        userName = request.userName,
                    ),
                )
            }.body()

        registrationChallengeToContext[response.challenge] = PendingPocRegistration(
            userId = request.userHandle,
            userName = request.userName,
        )

        val dto = PublicKeyCredentialCreationOptionsDto(
            rp = response.rp,
            user = response.user,
            challenge = response.challenge,
            pubKeyCredParams = response.pubKeyCredParams,
            timeoutMs = response.timeoutMs,
            excludeCredentials = response.excludeCredentials,
            authenticatorAttachment = response.authenticatorSelection?.authenticatorAttachment,
            residentKey = response.authenticatorSelection?.residentKey ?: "preferred",
            userVerification = response.authenticatorSelection?.userVerification ?: "preferred",
            attestation = response.attestation,
            extensions = response.extensions,
        )
        return WebAuthnDtoMapper.toModel(dto)
    }

    private suspend fun finishRegistrationAgainstPoc(request: RegistrationFinishPayload): Boolean {
        val context = registrationChallengeToContext.remove(request.challenge)
        val query = context?.userId?.let { "?userId=$it" }.orEmpty()

        val payload = PocRegistrationVerifyRequest(
            id = request.response.id,
            rawId = request.response.rawId,
            type = "public-key",
            response = request.response.response,
            clientExtensionResults = request.response.clientExtensionResults,
        )

        return runCatching {
            val response = httpClient.post("$endpointBase/register/verify$query") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(payload)
            }
            response.status.isSuccess() && response.body<PocVerificationResponse>().success
        }.onSuccess { verified ->
            if (verified && context != null) {
                registrationUserNameToUserId[context.userName] = context.userId
            }
        }.getOrDefault(false)
    }

    private suspend fun startAuthenticationAgainstPoc(
        request: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        val stableUserId = request.userHandle ?: registrationUserNameToUserId[request.userName] ?: request.userName
        val response: PocAuthenticationOptionsResponse =
            httpClient.post("$endpointBase/authenticate/options") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(PocAuthenticationOptionsRequest(userId = stableUserId))
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

    private suspend fun finishAuthenticationAgainstPoc(request: AuthenticationFinishPayload): Boolean {
        val payload = PocAuthenticationVerifyRequest(
            id = request.response.id,
            rawId = request.response.rawId,
            type = "public-key",
            response = request.response.response,
            clientExtensionResults = request.response.clientExtensionResults,
        )

        return runCatching {
            val response = httpClient.post("$endpointBase/authenticate/verify?challenge=${request.challenge}") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(payload)
            }
            response.status.isSuccess() && response.body<PocVerificationResponse>().success
        }.getOrDefault(false)
    }
}

@Serializable
private data class PocRegistrationOptionsRequest(
    val userId: String,
    val userName: String,
)

@Serializable
private data class PocAuthenticationOptionsRequest(
    val userId: String? = null,
)

@Serializable
private data class PocAuthenticatorSelectionDto(
    val authenticatorAttachment: String? = null,
    val residentKey: String = "preferred",
    val userVerification: String = "preferred",
)

@Serializable
private data class PocRegistrationOptionsResponse(
    val challenge: String,
    val rp: RpEntityDto,
    val user: UserEntityDto,
    val pubKeyCredParams: List<PublicKeyCredentialParametersDto>,
    @SerialName("timeout") val timeoutMs: Long? = null,
    val attestation: String? = null,
    val authenticatorSelection: PocAuthenticatorSelectionDto? = null,
    val excludeCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
private data class PocAuthenticationOptionsResponse(
    val challenge: String,
    val rpId: String,
    @SerialName("timeout") val timeoutMs: Long? = null,
    val userVerification: String = "preferred",
    val allowCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
)

@Serializable
private data class PocRegistrationVerifyRequest(
    val id: String,
    val rawId: String,
    val type: String,
    val response: RegistrationResponsePayloadDto,
    val clientExtensionResults: dev.webauthn.serialization.AuthenticationExtensionsClientOutputsDto? = null,
)

@Serializable
private data class PocAuthenticationVerifyRequest(
    val id: String,
    val rawId: String,
    val type: String,
    val response: AuthenticationResponsePayloadDto,
    val clientExtensionResults: dev.webauthn.serialization.AuthenticationExtensionsClientOutputsDto? = null,
)

@Serializable
private data class PocVerificationResponse(
    val success: Boolean,
    val message: String? = null,
)

private data class PendingPocRegistration(
    val userId: String,
    val userName: String,
)
