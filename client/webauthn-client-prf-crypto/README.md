# webauthn-client-prf-crypto

Audience: teams implementing client-side encryption flows derived from WebAuthn PRF assertion outputs.

## What it provides

- PRF request wiring on `PublicKeyCredentialRequestOptions`.
- PRF result extraction from `AuthenticationResponse`.
- HKDF-SHA256 deterministic AES-256 key derivation.
- AES-GCM encrypt/decrypt helpers and zeroizable `PrfCryptoSession`.
- `PrfCryptoClient.authenticateWithPrf(...)` for assertion and session derivation in one call.

<!-- diagram: client-webauthn-client-prf-crypto-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-prf-crypto-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/client-webauthn-client-prf-crypto-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/client-webauthn-client-prf-crypto-readme-1-desktop-dark.svg">
  <img alt="client-prf-crypto · What it provides. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/client-webauthn-client-prf-crypto-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: client-prf-crypto · What it provides</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: Caller-owned persisted salt; PublicKeyCredentialRequestOptions; PrfCrypto.withPrfEvaluation; PasskeyClient.getAssertion; PrfCrypto.requirePrfResults; HKDF-SHA256 deriveAes256Key; PrfCryptoSession (in memory); encrypt / encryptString; decrypt / decryptToString; clear() zeroizes key bytes.</p>
<p>1. Caller-owned persisted salt → PublicKeyCredentialRequestOptions.</p>
<p>2. PublicKeyCredentialRequestOptions → PrfCrypto.withPrfEvaluation.</p>
<p>3. PrfCrypto.withPrfEvaluation → PasskeyClient.getAssertion.</p>
<p>4. PasskeyClient.getAssertion → PrfCrypto.requirePrfResults.</p>
<p>5. PrfCrypto.requirePrfResults → HKDF-SHA256 deriveAes256Key.</p>
<p>6. HKDF-SHA256 deriveAes256Key → PrfCryptoSession (in memory).</p>
<p>7. PrfCryptoSession (in memory) → encrypt / encryptString.</p>
<p>8. PrfCryptoSession (in memory) → decrypt / decryptToString.</p>
<p>9. PrfCryptoSession (in memory) → clear() zeroizes key bytes.</p>
</details>
<!-- /diagram -->

## When to use

Use this module when app data must be encrypted with a key derived from a successful user-authenticated passkey assertion and your app is responsible for salt persistence/lifecycle policy.

## How to use

This flow checks PRF capability, authenticates with PRF, encrypts payload data, and returns the full AEAD payload for later decryption.

<!-- doc-example: id=client-webauthn-client-prf-crypto-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/PrfCryptoExample.kt#prf-crypto -->
```kotlin
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
```

Important usage notes:

- Persist the full `PrfCiphertext` (`nonce`, `ciphertext`, `authTag`, optional `associatedData`), not just ciphertext bytes.
- Persist salts in caller-owned durable storage; this module does not manage storage.
- Use a stable context string per encryption domain.
- Clear sessions on logout/app background teardown/flow completion.
- Coroutine cancellation is propagated unchanged; only non-cancellation failures are mapped to `PasskeyResult.Failure`.

## How it fits in the system

- Built on top of `webauthn-client-core` (`PasskeyClient` contract).
- Uses `webauthn-runtime-core` coroutine-boundary helpers so cancellation propagation is consistent with other client adapters.
- Complements `webauthn-client-compose` and platform modules when app-level encryption is required.
- Independent of server-side crypto verification; this is a client-side data-protection utility.

## Pitfalls and limits

- PRF availability depends on platform/authenticator support.
- `@ExperimentalWebAuthnL3Api` applies.
- No key rotation, secure enclave policy, or salt migration framework.

## iOS targets

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`.
- `iosX64` support was removed to align with upstream dependency artifacts and current CI target compatibility.

## Status

Beta, Signum-backed PRF crypto utility layer.
