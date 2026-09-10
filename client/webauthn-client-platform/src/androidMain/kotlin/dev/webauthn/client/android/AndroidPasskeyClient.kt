package dev.webauthn.client.android

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
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
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.DefaultPasskeyClient
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyCreateMediation
import dev.webauthn.client.PasskeyCreateOptions
import dev.webauthn.client.PasskeyPlatformBridge
import dev.webauthn.client.PlatformCapability
import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.client.platform.InvalidPlatformResponseException
import dev.webauthn.client.platform.PasskeyCodecException
import dev.webauthn.runtime.rethrowCancellationOrFatal
import kotlinx.coroutines.CancellationException

private const val RP_ID_VALIDATION_HINT =
    "Troubleshooting: verify RP ID/domain alignment, serve /.well-known/assetlinks.json over HTTPS, " +
        "and confirm your Android package name plus signing SHA-256 fingerprint match that file."

/**
 * Android `CredentialManager` backed [PasskeyClient] implementation.
 *
 * The supplied prompt context provider must resolve an Activity-backed context because passkey
 * ceremonies may launch system UI.
 */
public class AndroidPasskeyClient(
    private val contextProvider: PasskeyPromptContextProvider,
    private val credentialManagerFactory: (Context) -> CredentialManager = CredentialManager::create,
    private val codec: WebAuthnJsonCodec,
) : PasskeyClient by DefaultPasskeyClient(
    bridge = AndroidPasskeyPlatformBridge(
        contextProvider = contextProvider,
        credentialManagerFactory = credentialManagerFactory,
        codec = codec,
    ),
) {
    /**
     * Convenience constructor for apps that want default prompt-context handling.
     *
     * The client tracks current foreground activity when possible, while still allowing callers
     * to inject a custom [PasskeyPromptContextProvider] via the primary constructor when needed.
     */
    public constructor(
        context: Context,
        codec: WebAuthnJsonCodec,
        credentialManager: CredentialManager = CredentialManager.create(context),
    ) : this(
        contextProvider = defaultPromptContextProvider(context),
        credentialManagerFactory = { credentialManager },
        codec = codec,
    )

    /** Factory methods for explicitly owned Android passkey clients. */
    public companion object {
        /**
         * Creates a client that always presents Credential Manager UI from [activity].
         *
         * Use the primary constructor when the client outlives an activity and must resolve the
         * current foreground context through a [PasskeyPromptContextProvider].
         */
        public fun forActivity(
            activity: Activity,
            codec: WebAuthnJsonCodec,
        ): AndroidPasskeyClient {
            return AndroidPasskeyClient(
                contextProvider = PasskeyPromptContextProvider { activity },
                codec = codec,
            )
        }
    }
}

internal class AndroidPasskeyPlatformBridge(
    private val contextProvider: PasskeyPromptContextProvider,
    private val credentialManagerFactory: (Context) -> CredentialManager,
    private val codec: WebAuthnJsonCodec,
) : PasskeyPlatformBridge {
    /**
     * W3C WebAuthn L3: §5.1.3. Create a New Credential (createCredential)
     * Maps to Android Credential Manager CreatePublicKeyCredentialRequest
     */
    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RawRegistrationResponse {
        return createCredential(options, PasskeyCreateOptions.Default)
    }

    override suspend fun createCredential(
        options: PublicKeyCredentialCreationOptions,
        createOptions: PasskeyCreateOptions,
    ): RawRegistrationResponse {
        val context = requirePromptContext()
        val credentialManager = credentialManagerFactory(context)
        val conditionalCreate = createOptions.mediation == PasskeyCreateMediation.CONDITIONAL
        return runTypedCeremony(
            options = options,
            encodeOptions = codec::encodeCreationOptions,
            executeRequest = { requestJson ->
                credentialManager.createCredential(
                    context = context,
                    request = CreatePublicKeyCredentialRequest(
                        requestJson = requestJson,
                        preferImmediatelyAvailableCredentials = conditionalCreate,
                        isConditional = conditionalCreate,
                    ),
                )
            },
            extractPayload = { response -> requireCreatePublicKeyResponse(response).registrationResponseJson },
            decodePayload = { payload ->
                codec.decodeRegistrationResponse(payload).toPlatformValue("Failed to parse registration response JSON")
            },
        )
    }

    /**
     * W3C WebAuthn L3: §5.1.4. Use an Existing Credential to Make an Assertion (getAssertion)
     * Maps to Android Credential Manager GetCredentialRequest/GetPublicKeyCredentialOption
     */
    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): RawAuthenticationResponse {
        val context = requirePromptContext()
        val credentialManager = credentialManagerFactory(context)
        return runTypedCeremony(
            options = options,
            encodeOptions = codec::encodeRequestOptions,
            executeRequest = { requestJson ->
                credentialManager.getCredential(
                    context,
                    GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))),
                )
            },
            extractPayload = { response ->
                requirePublicKeyCredential(response).authenticationResponseJson
            },
            decodePayload = { payload ->
                codec.decodeAuthenticationResponse(payload)
                    .toPlatformValue("Failed to parse authentication response JSON")
            },
        )
    }

    override fun mapPlatformError(throwable: Throwable): PasskeyClientError = when (throwable) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled()
        is CreateCredentialNoCreateOptionException -> PasskeyClientError.Platform(
            "No credential creation option is available",
        )
        is NoCredentialException -> PasskeyClientError.NoCredential()
        is PasskeyCodecException -> PasskeyClientError.Codec(throwable.message ?: "Passkey codec failure")
        is InvalidPlatformResponseException -> PasskeyClientError.Platform(
            enrichRpIdValidationMessage(throwable.message ?: "Invalid platform response"),
        )
        is IllegalArgumentException -> PasskeyClientError.InvalidOptions(
            enrichRpIdValidationMessage(throwable.message ?: "Invalid options"),
        )
        else -> PasskeyClientError.Platform(
            enrichRpIdValidationMessage(throwable.message ?: "Unknown platform error"),
        )
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        val supportsExtensions = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        return PasskeyCapabilities(
            support = buildMap {
                put(
                    PasskeyCapability.Extension(WebAuthnExtension.Prf),
                    supportsExtensions.asCapabilitySupport(),
                )
                put(
                    PasskeyCapability.Extension(WebAuthnExtension.LargeBlob),
                    supportsExtensions.asCapabilitySupport(),
                )
                put(
                    PasskeyCapability.Platform(PlatformCapability.SecurityKey),
                    // Credential Manager does not expose a separate security-key capability probe.
                    CapabilitySupport.UNKNOWN,
                )
                put(
                    PasskeyCapability.Platform(PlatformCapability.ConditionalCreate),
                    CapabilitySupport.SUPPORTED,
                )
            },
        )
    }

    private fun requirePromptContext(): Context {
        val context = contextProvider.currentContextOrNull()
            ?: throw IllegalStateException("No active UI context available for passkey prompt")
        return context.findActivityOrNull()
            ?: throw IllegalStateException("Activity-backed context required for passkey prompt")
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
        val requestJson = runCodecOperation(
            failureMessage = "Failed to encode passkey options",
        ) {
            encodeOptions(options)
        }
        val platformResponse = executeRequest(requestJson)
        val responseJson = extractPayload(platformResponse)
        return runCodecOperation(
            failureMessage = "Failed to decode passkey response",
        ) {
            decodePayload(responseJson)
        }
    }
}

@Suppress("TooGenericExceptionCaught")
private inline fun <T> runCodecOperation(
    failureMessage: String,
    operation: () -> T,
): T {
    return try {
        operation()
    } catch (error: Throwable) {
        val nonFatal = error.rethrowCancellationOrFatal()
        val codecFailure = nonFatal as? PasskeyCodecException
            ?: PasskeyCodecException(failureMessage, nonFatal)
        throw codecFailure
    }
}

private fun enrichRpIdValidationMessage(message: String): String {
    if (!looksLikeRpIdValidationFailure(message)) {
        return message
    }
    return "$message. $RP_ID_VALIDATION_HINT"
}

private fun Boolean.asCapabilitySupport(): CapabilitySupport =
    if (this) CapabilitySupport.SUPPORTED else CapabilitySupport.UNSUPPORTED

private fun <T> ValidationResult<T>.toPlatformValue(context: String): T = when (this) {
    is ValidationResult.Valid -> value
    is ValidationResult.Invalid -> {
        val error = errors.firstOrNull()
        val message = "$context: ${error?.field ?: "response"}: ${error?.message ?: "Unknown validation error"}"
        throw PasskeyCodecException(message)
    }
}

private fun looksLikeRpIdValidationFailure(message: String): Boolean {
    val normalized = message.lowercase()
    val mentionsRpId = normalized.contains("rp id") || normalized.contains("rpid")
    val mentionsValidationFailure = normalized.contains("cannot be validated") ||
        normalized.contains("can't be validated") ||
        normalized.contains("cannot be verified")
    return mentionsRpId && mentionsValidationFailure
}

private fun Context.findActivityOrNull(): Activity? {
    var cursor: Context? = this
    while (cursor is ContextWrapper) {
        if (cursor is Activity) {
            return cursor
        }
        cursor = cursor.baseContext
    }
    return cursor as? Activity
}

private fun defaultPromptContextProvider(context: Context): PasskeyPromptContextProvider {
    val application = context.applicationContext as? Application
    return if (application != null) {
        ForegroundActivityPasskeyPromptContextProvider.forApplication(
            application = application,
            contextHint = context,
        )
    } else {
        MutablePasskeyPromptContextProvider(context)
    }
}
