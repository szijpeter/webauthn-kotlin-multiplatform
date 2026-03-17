@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client.prf

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import kotlinx.coroutines.CancellationException

@ExperimentalWebAuthnL3Api
/** Result bundle for a PRF-enabled assertion and its derived crypto session. */
public data class PrfAuthenticationResult(
    public val response: AuthenticationResponse,
    public val prfResults: AuthenticationExtensionsPRFValues,
    public val session: PrfCryptoSession,
)

@ExperimentalWebAuthnL3Api
/** High-level facade that executes assertion + PRF session derivation in one call. */
public class PrfCryptoClient(
    private val passkeyClient: PasskeyClient,
) {
    public suspend fun authenticateWithPrf(
        options: PublicKeyCredentialRequestOptions,
        salts: AuthenticationExtensionsPRFValues,
        context: String = PrfCrypto.DEFAULT_CONTEXT,
        hkdfSalt: Base64UrlBytes? = null,
        outputSelection: PrfOutputSelection = PrfOutputSelection.FIRST,
    ): PasskeyResult<PrfAuthenticationResult> {
        val optionsWithPrf = PrfCrypto.withPrfEvaluation(options, salts)
        val assertion = runCatching { passkeyClient.getAssertion(optionsWithPrf) }
            .getOrElse { error -> return error.toFailure() }
        return when (assertion) {
            is PasskeyResult.Failure -> assertion
            is PasskeyResult.Success -> {
                runCatching {
                    val results = PrfCrypto.requirePrfResults(assertion.value)
                    val session = PrfCrypto.createSession(
                        prfResults = results,
                        outputSelection = outputSelection,
                        context = context,
                        hkdfSalt = hkdfSalt,
                    )
                    PrfAuthenticationResult(
                        response = assertion.value,
                        prfResults = results,
                        session = session,
                    )
                }.fold(
                    onSuccess = { PasskeyResult.Success(it) },
                    onFailure = { error -> error.toFailure() },
                )
            }
        }
    }
}

private fun Throwable.toFailure(): PasskeyResult.Failure {
    if (this is CancellationException) throw this
    return when (this) {
        is MissingPrfOutputException -> {
            PasskeyResult.Failure(PasskeyClientError.InvalidOptions(message ?: "Missing PRF output"))
        }

        is IllegalArgumentException -> {
            PasskeyResult.Failure(PasskeyClientError.InvalidOptions(message ?: "Invalid PRF options"))
        }

        else -> {
            PasskeyResult.Failure(
                PasskeyClientError.Platform(
                    message = message ?: "PRF crypto operation failed",
                    cause = this,
                ),
            )
        }
    }
}
