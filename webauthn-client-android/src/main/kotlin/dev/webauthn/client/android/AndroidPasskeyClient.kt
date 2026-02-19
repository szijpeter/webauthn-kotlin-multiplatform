package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import at.asitplus.KmmResult
import at.asitplus.catching
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

public class AndroidPasskeyClient(
    private val context: Context,
    private val credentialManager: CredentialManager = CredentialManager.create(context),
) : PasskeyClient {
    private val requestJson = Json { encodeDefaults = false }
    private val responseJson = Json { ignoreUnknownKeys = true }

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        if (options.pubKeyCredParams.isEmpty()) {
            return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("pubKeyCredParams must not be empty"))
        }

        return createRequest(options)
            .transform { request -> catching { credentialManager.createCredential(context, request) } }
            .transform(::requireCreatePublicKeyResponse)
            .transform { response -> parseRegistrationDto(response.registrationResponseJson) }
            .transform(::toRegistrationModel)
            .toPasskeyResult()
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return createGetOption(options)
            .transform { option -> catching { credentialManager.getCredential(context, GetCredentialRequest(listOf(option))) } }
            .transform(::requirePublicKeyCredential)
            .transform { credential -> parseAuthenticationDto(credential.authenticationResponseJson) }
            .transform(::toAuthenticationModel)
            .toPasskeyResult()
    }

    private fun <T> KmmResult<T>.toPasskeyResult(): PasskeyResult<T> = fold(
        onSuccess = { PasskeyResult.Success(it) },
        onFailure = { error -> PasskeyResult.Failure(error.toPasskeyClientError()) },
    )

    private fun createRequest(options: PublicKeyCredentialCreationOptions): KmmResult<CreatePublicKeyCredentialRequest> = catching {
        CreatePublicKeyCredentialRequest(
            requestJson.encodeToString(
                PublicKeyCredentialCreationOptionsDto.serializer(),
                WebAuthnDtoMapper.fromModel(options),
            ),
        )
    }

    private fun createGetOption(options: PublicKeyCredentialRequestOptions): KmmResult<GetPublicKeyCredentialOption> = catching {
        GetPublicKeyCredentialOption(
            requestJson.encodeToString(
                PublicKeyCredentialRequestOptionsDto.serializer(),
                WebAuthnDtoMapper.fromModel(options),
            ),
        )
    }

    private fun requireCreatePublicKeyResponse(response: CreateCredentialResponse): KmmResult<CreatePublicKeyCredentialResponse> =
        when (response) {
            is CreatePublicKeyCredentialResponse -> KmmResult(response)
            else -> failureResult("Unexpected response type: ${response::class.simpleName}")
        }

    private fun requirePublicKeyCredential(response: GetCredentialResponse): KmmResult<PublicKeyCredential> {
        val credential = response.credential
        return if (credential is PublicKeyCredential) {
            KmmResult(credential)
        } else {
            failureResult("Unexpected credential type: ${credential::class.simpleName}")
        }
    }

    private fun parseRegistrationDto(responseJsonPayload: String): KmmResult<RegistrationResponseDto> =
        parseDto(
            responseJsonPayload = responseJsonPayload,
            serializer = RegistrationResponseDto.serializer(),
            ceremony = "registration",
        )

    private fun parseAuthenticationDto(responseJsonPayload: String): KmmResult<AuthenticationResponseDto> =
        parseDto(
            responseJsonPayload = responseJsonPayload,
            serializer = AuthenticationResponseDto.serializer(),
            ceremony = "authentication",
        )

    private fun <T> parseDto(
        responseJsonPayload: String,
        serializer: KSerializer<T>,
        ceremony: String,
    ): KmmResult<T> =
        catching {
            responseJson.decodeFromString(serializer, responseJsonPayload)
        }.mapFailure { throwable ->
            IllegalArgumentException("Failed to parse $ceremony response JSON: ${throwable.message}", throwable)
        }

    private fun toRegistrationModel(dto: RegistrationResponseDto): KmmResult<RegistrationResponse> =
        when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
            is ValidationResult.Valid -> KmmResult(modelResult.value)
            is ValidationResult.Invalid -> {
                val firstError = modelResult.errors.first()
                failureResult("${firstError.field}: ${firstError.message}")
            }
        }

    private fun toAuthenticationModel(dto: AuthenticationResponseDto): KmmResult<AuthenticationResponse> =
        when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
            is ValidationResult.Valid -> KmmResult(modelResult.value)
            is ValidationResult.Invalid -> {
                val firstError = modelResult.errors.first()
                failureResult("${firstError.field}: ${firstError.message}")
            }
        }

    private fun <T> failureResult(message: String): KmmResult<T> =
        KmmResult(IllegalArgumentException(message))

    private fun Throwable.toPasskeyClientError(): PasskeyClientError = when (this) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled()
        is NoCredentialException -> PasskeyClientError.Platform("No credentials found")
        else -> PasskeyClientError.Platform(this.message ?: "Unknown platform error", this)
    }
}
