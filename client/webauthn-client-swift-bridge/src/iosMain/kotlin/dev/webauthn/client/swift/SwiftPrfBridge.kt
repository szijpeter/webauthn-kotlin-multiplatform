@file:OptIn(dev.webauthn.model.ExperimentalWebAuthnL3Api::class)

package dev.webauthn.client.swift

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyResult
import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.ValidationResult
import dev.webauthn.runtime.rethrowCancellationOrFatal
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

/** Stable PRF authentication result exported only to the internal Swift adapter. */
public class SwiftPrfAuthenticationBridgeResult internal constructor(
    public val responseJson: String?,
    public val firstResultBase64Url: String?,
    public val secondResultBase64Url: String?,
    public val errorCode: String?,
    public val errorMessage: String?,
) {
    public val isSuccess: Boolean
        get() = responseJson != null && firstResultBase64Url != null &&
            errorCode == null && errorMessage == null
}

internal class SwiftPrfBridge(
    private val passkeyClient: PasskeyClient,
    private val codec: WebAuthnJsonCodec = KotlinxWebAuthnJsonCodec(),
) {
    @Suppress("TooGenericExceptionCaught")
    suspend fun authenticate(
        requestJson: String,
        firstSaltBase64Url: String,
        secondSaltBase64Url: String?,
    ): SwiftPrfAuthenticationBridgeResult {
        val options = when (val decoded = codec.decodeRequestOptions(requestJson)) {
            is ValidationResult.Valid -> decoded.value
            is ValidationResult.Invalid -> {
                return prfFailure("invalidOptions", "Authentication options JSON is invalid.")
            }
        }
        val salts = try {
            AuthenticationExtensionsPRFValues(
                first = Base64UrlBytes.parseOrThrow(firstSaltBase64Url, "firstSalt"),
                second = secondSaltBase64Url?.let { Base64UrlBytes.parseOrThrow(it, "secondSalt") },
            )
        } catch (_: IllegalArgumentException) {
            return prfFailure("invalidOptions", "A PRF salt is invalid.")
        }
        val existingExtensions = options.extensions ?: AuthenticationExtensionsClientInputs()
        val optionsWithPrf = options.copy(
            extensions = existingExtensions.copy(
                prf = (existingExtensions.prf ?: PrfExtensionInput()).copy(
                    eval = salts,
                    evalByCredential = null,
                ),
            ),
        )

        return when (val result = passkeyClient.getAssertion(optionsWithPrf)) {
            is PasskeyResult.Failure -> result.error.toSwiftBridgeFailure().let { failure ->
                prfFailure(failure.code, failure.message)
            }

            is PasskeyResult.Success -> try {
                val prfResults = result.value.extensions?.prf?.results
                    ?: return prfFailure(
                        "invalidOptions",
                        "PRF extension was requested but no PRF results were returned by the authenticator.",
                    )
                SwiftPrfAuthenticationBridgeResult(
                    responseJson = codec.encodeAuthenticationResponse(result.value),
                    firstResultBase64Url = prfResults.first.encoded(),
                    secondResultBase64Url = prfResults.second?.encoded(),
                    errorCode = null,
                    errorMessage = null,
                )
            } catch (error: Throwable) {
                error.rethrowCancellationOrFatal()
                prfFailure("codec", "Failed to encode authentication response JSON.")
            }
        }
    }
}

internal fun prfFailure(code: String, message: String): SwiftPrfAuthenticationBridgeResult =
    SwiftPrfAuthenticationBridgeResult(
        responseJson = null,
        firstResultBase64Url = null,
        secondResultBase64Url = null,
        errorCode = code,
        errorMessage = message,
    )
