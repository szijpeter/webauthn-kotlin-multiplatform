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
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.SharedPasskeyClient

public class AndroidPasskeyClient(
    private val context: Context,
    private val credentialManager: CredentialManager = CredentialManager.create(context),
) : PasskeyClient by SharedPasskeyClient(
    bridge = AndroidPasskeyPlatformBridge(
        context = context,
        credentialManager = credentialManager,
    ),
    jsonCodec = AndroidKotlinxPasskeyJsonCodec(),
)

internal class AndroidPasskeyPlatformBridge(
    private val context: Context,
    private val credentialManager: CredentialManager,
) : PasskeyPlatformBridge {
    override suspend fun createCredential(requestJson: String): String {
        val response = credentialManager.createCredential(
            context = context,
            request = CreatePublicKeyCredentialRequest(requestJson),
        )

        return requireCreatePublicKeyResponse(response).registrationResponseJson
    }

    override suspend fun getAssertion(requestJson: String): String {
        val response = credentialManager.getCredential(
            context,
            GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))),
        )

        return requirePublicKeyCredential(response).authenticationResponseJson
    }

    override fun mapPlatformError(throwable: Throwable): PasskeyClientError = when (throwable) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled()
        is NoCredentialException -> PasskeyClientError.Platform("No credentials found")
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
}
