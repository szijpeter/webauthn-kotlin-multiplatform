package dev.webauthn.network

import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
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

public enum class WebAuthnBackendProfile {
    LIBRARY_ROUTES,
    PASSKEY_ENCRYPTION_POC,
}

public class KtorPasskeyServerClient(
    private val httpClient: HttpClient,
    private val endpointBase: String,
    private val profile: WebAuthnBackendProfile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
) : PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload> {
    private val registrationChallengeToContext: MutableMap<String, PendingPocRegistration> = mutableMapOf()
    private val registrationUserNameToUserId: MutableMap<String, String> = mutableMapOf()

    override suspend fun getRegisterOptions(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> startRegistrationAgainstLibrary(params)
            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> startRegistrationAgainstPoc(params)
        }
    }

    override suspend fun finishRegister(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> finishRegistrationAgainstLibrary(
                params = params,
                response = response,
                challengeAsBase64Url = challengeAsBase64Url,
            )

            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> finishRegistrationAgainstPoc(
                response = response,
                challengeAsBase64Url = challengeAsBase64Url,
            )
        }
    }

    override suspend fun getSignInOptions(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> startAuthenticationAgainstLibrary(params)
            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> startAuthenticationAgainstPoc(params)
        }
    }

    override suspend fun finishSignIn(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        return when (profile) {
            WebAuthnBackendProfile.LIBRARY_ROUTES -> finishAuthenticationAgainstLibrary(
                params = params,
                response = response,
                challengeAsBase64Url = challengeAsBase64Url,
            )

            WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC -> finishAuthenticationAgainstPoc(
                response = response,
                challengeAsBase64Url = challengeAsBase64Url,
            )
        }
    }

    private suspend fun startRegistrationAgainstLibrary(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        val dto: PublicKeyCredentialCreationOptionsDto =
            httpClient.post("$endpointBase/webauthn/registration/start") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(params)
            }.body()

        return WebAuthnDtoMapper.toModel(dto)
    }

    private suspend fun finishRegistrationAgainstLibrary(
        params: RegistrationStartPayload,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val finishPayload = LibraryRegistrationFinishPayload(
            response = responseDto,
            clientDataType = "webauthn.create",
            challenge = challengeAsBase64Url,
            origin = params.origin,
        )
        val result: FinishPayloadResponse =
            httpClient.post("$endpointBase/webauthn/registration/finish") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(finishPayload)
            }.body()
        return result.status == "ok"
    }

    private suspend fun startAuthenticationAgainstLibrary(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        val dto: PublicKeyCredentialRequestOptionsDto =
            httpClient.post("$endpointBase/webauthn/authentication/start") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(params)
            }.body()

        return WebAuthnDtoMapper.toModel(dto)
    }

    private suspend fun finishAuthenticationAgainstLibrary(
        params: AuthenticationStartPayload,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val finishPayload = LibraryAuthenticationFinishPayload(
            response = responseDto,
            clientDataType = "webauthn.get",
            challenge = challengeAsBase64Url,
            origin = params.origin,
        )
        val result: FinishPayloadResponse =
            httpClient.post("$endpointBase/webauthn/authentication/finish") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(finishPayload)
            }.body()
        return result.status == "ok"
    }

    private suspend fun startRegistrationAgainstPoc(
        params: RegistrationStartPayload,
    ): ValidationResult<PublicKeyCredentialCreationOptions> {
        val response: PocRegistrationOptionsResponse =
            httpClient.post("$endpointBase/register/options") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(
                    PocRegistrationOptionsRequest(
                        userId = params.userHandle,
                        userName = params.userName,
                    ),
                )
            }.body()

        registrationChallengeToContext[response.challenge] = PendingPocRegistration(
            userId = params.userHandle,
            userName = params.userName,
        )

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

    private suspend fun finishRegistrationAgainstPoc(
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val context = registrationChallengeToContext.remove(challengeAsBase64Url)
        val query = context?.userId?.let { "?userId=$it" }.orEmpty()

        val payload = PocRegistrationVerifyRequest(
            id = responseDto.id,
            rawId = responseDto.rawId,
            type = "public-key",
            response = responseDto.response,
            clientExtensionResults = responseDto.clientExtensionResults,
        )

        return runCatching {
            val httpResponse = httpClient.post("$endpointBase/register/verify$query") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(payload)
            }
            httpResponse.status.isSuccess() && httpResponse.body<PocVerificationResponse>().success
        }.onSuccess { verified ->
            if (verified && context != null) {
                registrationUserNameToUserId[context.userName] = context.userId
            }
        }.getOrDefault(false)
    }

    private suspend fun startAuthenticationAgainstPoc(
        params: AuthenticationStartPayload,
    ): ValidationResult<PublicKeyCredentialRequestOptions> {
        val stableUserId = params.userHandle ?: registrationUserNameToUserId[params.userName] ?: params.userName
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

    private suspend fun finishAuthenticationAgainstPoc(
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): Boolean {
        val responseDto = WebAuthnDtoMapper.fromModel(response)
        val payload = PocAuthenticationVerifyRequest(
            id = responseDto.id,
            rawId = responseDto.rawId,
            type = "public-key",
            response = responseDto.response,
            clientExtensionResults = responseDto.clientExtensionResults,
        )

        return runCatching {
            val httpResponse = httpClient.post("$endpointBase/authenticate/verify?challenge=$challengeAsBase64Url") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                setBody(payload)
            }
            httpResponse.status.isSuccess() && httpResponse.body<PocVerificationResponse>().success
        }.getOrDefault(false)
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
private data class LibraryRegistrationFinishPayload(
    val response: dev.webauthn.serialization.RegistrationResponseDto,
    val clientDataType: String,
    val challenge: String,
    val origin: String,
)

@Serializable
private data class LibraryAuthenticationFinishPayload(
    val response: dev.webauthn.serialization.AuthenticationResponseDto,
    val clientDataType: String,
    val challenge: String,
    val origin: String,
)

@Serializable
private data class FinishPayloadResponse(
    val status: String,
)

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
    val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
)

@Serializable
private data class PocAuthenticationVerifyRequest(
    val id: String,
    val rawId: String,
    val type: String,
    val response: AuthenticationResponsePayloadDto,
    val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
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
