# webauthn-client-prf-crypto

Audience: teams implementing client-side crypto workflows backed by WebAuthn PRF extension outputs.

## What it provides

- PRF request wiring helpers for `PublicKeyCredentialRequestOptions`.
- PRF result extraction/validation helpers from authentication responses.
- HKDF-SHA256 deterministic AES-256 key derivation from PRF output.
- AES-GCM encrypt/decrypt helpers and a zeroizable in-memory `PrfCryptoSession`.
- High-level `PrfCryptoClient.authenticateWithPrf(...)` facade for assertion + session derivation.

```mermaid
flowchart TD
    Salt[Caller-owned persisted salt] --> Start[PublicKeyCredentialRequestOptions]
    Start --> AddPrf[PrfCrypto.withPrfEvaluation]
    AddPrf --> Assertion[PasskeyClient.getAssertion]
    Assertion --> Extract[PrfCrypto.requirePrfResults]
    Extract --> Derive[HKDF-SHA256 deriveAes256Key]
    Derive --> Session[PrfCryptoSession in memory]
    Session --> Encrypt[encrypt/encryptString]
    Session --> Decrypt[decrypt/decryptToString]
    Session --> Clear[clear() zeroizes key bytes]
```

## Threat-model fit

This module is designed for app-level encrypted data flows where keys are derived from user-authenticated passkey assertions and where callers explicitly control salt persistence and key lifecycle policy.

## How to use

A typical sign-in flow checks PRF capability, loads caller-owned salt, derives a session, encrypts data, then clears session memory.

```kotlin
import dev.webauthn.client.PasskeyResult
import dev.webauthn.client.prf.PrfCryptoClient
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.ExperimentalWebAuthnL3Api

@OptIn(ExperimentalWebAuthnL3Api::class)
suspend fun deriveAndEncrypt(
    passkeyClient: dev.webauthn.client.PasskeyClient,
    requestOptions: dev.webauthn.model.PublicKeyCredentialRequestOptions,
    persistedSalt: dev.webauthn.model.Base64UrlBytes,
): PasskeyResult<String> {
    if (!passkeyClient.capabilities().supportsPrf) {
        return PasskeyResult.Failure(dev.webauthn.client.PasskeyClientError.InvalidOptions("PRF not supported"))
    }

    val client = PrfCryptoClient(passkeyClient)
    val auth = client.authenticateWithPrf(
        options = requestOptions,
        salts = AuthenticationExtensionsPRFValues(first = persistedSalt),
        context = "myapp.prf.v1",
    )

    return when (auth) {
        is PasskeyResult.Failure -> auth
        is PasskeyResult.Success -> {
            val session = auth.value.session
            try {
                val ciphertext = session.encryptString("sensitive payload")
                PasskeyResult.Success(ciphertext.ciphertext.encoded())
            } finally {
                session.clear()
            }
        }
    }
}
```

Key API behaviors:

- `authenticateWithPrf(...)` wraps assertion + PRF result extraction + session derivation.
- `PrfOutputSelection` controls whether first/second PRF output is used.
- `MissingPrfOutputException` is mapped to typed passkey failure (`InvalidOptions`).
- `PrfCryptoSession` enforces post-clear usage checks.

## Key lifecycle checklist

- Persist salts in caller-owned durable storage.
- Use a stable context string per encryption domain.
- Clear in-memory sessions at logout, background teardown, or flow completion.
- Treat session fingerprints as diagnostics only, not as secrets.

## Limits

- Does not manage salt storage, key rotation, or secure enclave/keychain policy.
- PRF availability is authenticator/platform dependent.
- API is experimental via `@ExperimentalWebAuthnL3Api`.

## Status

Beta, Signum-backed PRF crypto utilities for client flows.
