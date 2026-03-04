package dev.webauthn.client.android

import android.content.Context
import android.os.Build
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import dev.webauthn.client.decodeAuthenticationResponseOrThrowPlatform
import dev.webauthn.client.decodeRegistrationResponseOrThrowPlatform
import dev.webauthn.client.encodeAssertionOptionsOrThrowInvalid
import dev.webauthn.client.encodeCreationOptionsOrThrowInvalid
import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyJsonMapper
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

public class AndroidPasskeyClient(
    private val context: Context,
    private val credentialManager: CredentialManager = CredentialManager.create(context),
) : PasskeyClient by DefaultPasskeyClient(
    bridge = AndroidPasskeyPlatformBridge(
        context = context,
        credentialManager = credentialManager,
    ),
)

internal class AndroidPasskeyPlatformBridge(
    private val context: Context,
    private val credentialManager: CredentialManager,
    private val jsonMapper: PasskeyJsonMapper = KotlinxPasskeyJsonMapper(),
) : PasskeyPlatformBridge {
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RegistrationResponse {
        return runTypedCeremony(
            options = options,
            encodeOptions = jsonMapper::encodeCreationOptionsOrThrowInvalid,
            executeRequest = { requestJson ->
                credentialManager.createCredential(
                    context = context,
                    request = CreatePublicKeyCredentialRequest(requestJson),
                )
            },
            extractPayload = { response -> requireCreatePublicKeyResponse(response).registrationResponseJson },
            decodePayload = jsonMapper::decodeRegistrationResponseOrThrowPlatform,
        )
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): AuthenticationResponse {
        return runTypedCeremony(
            options = options,
            encodeOptions = jsonMapper::encodeAssertionOptionsOrThrowInvalid,
            executeRequest = { requestJson ->
                credentialManager.getCredential(
                    context,
                    GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))),
                )
            },
            extractPayload = { response -> requirePublicKeyCredential(response).authenticationResponseJson },
            decodePayload = jsonMapper::decodeAuthenticationResponseOrThrowPlatform,
        )
    }

    override fun mapPlatformError(throwable: Throwable): PasskeyClientError = when (throwable) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled()
        is NoCredentialException -> PasskeyClientError.Platform("No credentials found")
        is IllegalArgumentException -> PasskeyClientError.InvalidOptions(throwable.message ?: "Invalid options")
        else -> PasskeyClientError.Platform(throwable.message ?: "Unknown platform error", throwable)
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        val supportsExtensions = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        return PasskeyCapabilities(
            supportsPrf = supportsExtensions,
            supportsLargeBlobRead = supportsExtensions,
            supportsLargeBlobWrite = supportsExtensions,
            supportsSecurityKey = true,
            platformVersionHints = listOf("androidSdk=${Build.VERSION.SDK_INT}"),
        )
    }

    private fun requireCreatePublicKeyResponse(response: CreateCredentialResponse): CreatePublicKeyCredentialResponse {
        return when (response) {
            is CreatePublicKeyCredentialResponse -> response
            else -> throw IllegalStateException("Unexpected response type: ${response::class.simpleName}")
        }
    }

    private fun requirePublicKeyCredential(response: GetCredentialResponse): PublicKeyCredential {
        val credential = response.credential
        return credential as? PublicKeyCredential
            ?: throw IllegalStateException("Unexpected credential type: ${credential::class.simpleName}")
    }

    private suspend fun <TOptions, TPlatformResponse, TModel> runTypedCeremony(
        options: TOptions,
        encodeOptions: (TOptions) -> String,
        executeRequest: suspend (String) -> TPlatformResponse,
        extractPayload: (TPlatformResponse) -> String,
        decodePayload: (String) -> TModel,
    ): TModel {
        val requestJson = encodeOptions(options)
        val platformResponse = executeRequest(requestJson)
        val responseJson = extractPayload(platformResponse)
        return decodePayload(responseJson)
    }
}
