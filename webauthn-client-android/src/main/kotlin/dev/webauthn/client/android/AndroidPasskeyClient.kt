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
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyJsonMapper
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

private const val RP_ID_VALIDATION_HINT =
    "Troubleshooting: verify RP ID/domain alignment, serve /.well-known/assetlinks.json over HTTPS, " +
        "and confirm your Android package name plus signing SHA-256 fingerprint match that file."

/**
 * Android `CredentialManager` backed [PasskeyClient] implementation.
 *
 * The supplied [context] must be an Activity context because passkey ceremonies
 * may launch system UI.
 */
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
    /**
     * W3C WebAuthn L3: §5.1.3. Create a New Credential (createCredential)
     * Maps to Android Credential Manager CreatePublicKeyCredentialRequest
     */
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

    /**
     * W3C WebAuthn L3: §5.1.4. Use an Existing Credential to Make an Assertion (getAssertion)
     * Maps to Android Credential Manager GetCredentialRequest/GetPublicKeyCredentialOption
     */
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
        is IllegalArgumentException -> PasskeyClientError.InvalidOptions(
            enrichRpIdValidationMessage(throwable.message ?: "Invalid options"),
        )
        else -> PasskeyClientError.Platform(
            enrichRpIdValidationMessage(throwable.message ?: "Unknown platform error"),
            throwable,
        )
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        val supportsExtensions = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        return PasskeyCapabilities(
            capabilities = mapOf(
                PasskeyCapability.Prf to supportsExtensions,
                PasskeyCapability.LargeBlob to supportsExtensions,
                PasskeyCapability.SecurityKey to true,
            ),
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

private fun enrichRpIdValidationMessage(message: String): String {
    if (!looksLikeRpIdValidationFailure(message)) {
        return message
    }
    return "$message. $RP_ID_VALIDATION_HINT"
}

private fun looksLikeRpIdValidationFailure(message: String): Boolean {
    val normalized = message.lowercase()
    val mentionsRpId = normalized.contains("rp id") || normalized.contains("rpid")
    val mentionsValidationFailure = normalized.contains("cannot be validated") ||
        normalized.contains("can't be validated") ||
        normalized.contains("cannot be verified")
    return mentionsRpId && mentionsValidationFailure
}
