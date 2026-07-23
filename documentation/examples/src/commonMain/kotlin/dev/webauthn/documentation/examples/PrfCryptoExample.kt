package dev.webauthn.documentation.examples

// docs-region prf-crypto
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.prf.PrfCiphertext
import dev.webauthn.client.prf.PrfCryptoClient
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.WebAuthnExtension

@OptIn(ExperimentalWebAuthnL3Api::class)
suspend fun authenticateAndEncrypt(
    passkeyClient: PasskeyClient,
    requestOptions: PublicKeyCredentialRequestOptions,
    persistedSalt: Base64UrlBytes,
    plaintext: String,
): PasskeyResult<PrfCiphertext> {
    if (!passkeyClient.capabilities().supports(PasskeyCapability.Extension(WebAuthnExtension.Prf))) {
        return PasskeyResult.Failure(
            PasskeyClientError.InvalidOptions("PRF is not supported on this platform/authenticator"),
        )
    }

    val prfClient = PrfCryptoClient(passkeyClient)
    return when (
        val auth = prfClient.authenticateWithPrf(
            options = requestOptions,
            salts = AuthenticationExtensionsPRFValues(first = persistedSalt),
            context = "myapp.storage.v1",
        )
    ) {
        is PasskeyResult.Failure -> auth
        is PasskeyResult.Success -> {
            val session = auth.value.session
            try {
                val associatedData = auth.value.response.credentialId.value.bytes()
                val sealed = session.encryptString(
                    plaintext = plaintext,
                    associatedData = associatedData,
                )
                PasskeyResult.Success(sealed)
            } finally {
                session.clear()
            }
        }
    }
}
// docs-endregion prf-crypto
