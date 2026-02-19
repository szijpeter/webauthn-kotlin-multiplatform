package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.PublicKeyCredential
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.model.ValidationResult

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

        return try {
            val request = CreatePublicKeyCredentialRequest(
                requestJson.encodeToString(
                    PublicKeyCredentialCreationOptionsDto.serializer(),
                    WebAuthnDtoMapper.fromModel(options),
                ),
            )
            val response = credentialManager.createCredential(context, request)
            if (response !is CreatePublicKeyCredentialResponse) {
                return PasskeyResult.Failure(
                    PasskeyClientError.Platform("Unexpected response type: ${response::class.simpleName}"),
                )
            }

            val dto = try {
                responseJson.decodeFromString(RegistrationResponseDto.serializer(), response.registrationResponseJson)
            } catch (e: Exception) {
                return PasskeyResult.Failure(PasskeyClientError.Platform("Failed to parse registration response JSON: ${e.message}", e))
            }

            return when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
                is ValidationResult.Valid -> PasskeyResult.Success(modelResult.value)
                is ValidationResult.Invalid -> {
                    val firstError = modelResult.errors.first()
                    PasskeyResult.Failure(PasskeyClientError.Platform("${firstError.field}: ${firstError.message}"))
                }
            }
        } catch (e: CreateCredentialException) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        } catch (e: Throwable) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        }
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        return try {
            val request = GetPublicKeyCredentialOption(
                requestJson.encodeToString(
                    PublicKeyCredentialRequestOptionsDto.serializer(),
                    WebAuthnDtoMapper.fromModel(options),
                ),
            )
            val response = credentialManager.getCredential(context, GetCredentialRequest(listOf(request)))
            val credential = response.credential
            if (credential !is PublicKeyCredential) {
                return PasskeyResult.Failure(PasskeyClientError.Platform("Unexpected credential type: ${credential::class.simpleName}"))
            }

            val dto = try {
                responseJson.decodeFromString(AuthenticationResponseDto.serializer(), credential.authenticationResponseJson)
            } catch (e: Exception) {
                return PasskeyResult.Failure(PasskeyClientError.Platform("Failed to parse authentication response JSON: ${e.message}", e))
            }

            return when (val modelResult = WebAuthnDtoMapper.toModel(dto)) {
                is ValidationResult.Valid -> PasskeyResult.Success(modelResult.value)
                is ValidationResult.Invalid -> {
                    val firstError = modelResult.errors.first()
                    PasskeyResult.Failure(PasskeyClientError.Platform("${firstError.field}: ${firstError.message}"))
                }
            }
        } catch (e: GetCredentialException) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        } catch (e: Throwable) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        }
    }

    private fun Throwable.toPasskeyClientError(): PasskeyClientError = when (this) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled()
        is NoCredentialException -> PasskeyClientError.Platform("No credentials found")
        else -> PasskeyClientError.Platform(this.message ?: "Unknown platform error", this)
    }
}
