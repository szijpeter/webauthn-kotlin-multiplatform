# PRF application crypto

The PRF extension can derive stable credential-bound output during an authentication ceremony. The optional `webauthn-client-prf-crypto` module turns that output into a short-lived AES-256 key session through HKDF-SHA256 and provides AES-GCM helpers.

## Ownership model

<!-- doc-example: id=site-prf-ownership-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Shows application ownership around the PRF crypto helper -->
```mermaid
flowchart LR
    Salt[(App-persisted salt)] --> Assertion[Passkey assertion with PRF]
    Assertion --> Output[Credential-bound PRF output]
    Output --> HKDF[HKDF with stable context]
    HKDF --> Session[Short-lived crypto session]
    Session --> AEAD[AES-GCM ciphertext package]
    Session --> Clear[Explicit key clear]
    AEAD --> Storage[(App-owned durable storage)]
```

The application owns salt generation and persistence, stable context naming, associated data, ciphertext storage, key/session lifetime, recovery, credential migration, and fallback behavior. The module does not provide account recovery or a secure enclave policy.

## Safe sequence

1. Probe `PasskeyCapability.Extension(WebAuthnExtension.Prf)` at runtime.
2. Load or generate a per-policy salt and persist it independently of the ephemeral session.
3. Authenticate with PRF evaluation requested.
4. Derive a key under a stable, versioned context.
5. Encrypt with meaningful associated data and persist the complete `PrfCiphertext` package.
6. Clear the session in `finally` and on logout/background teardown as appropriate.

## Migration and recovery

Version salts, contexts, and ciphertext formats. Decide how encrypted data migrates when a user adds, removes, or replaces passkeys. If the only usable credential disappears, derived data may be unrecoverable. A fallback that silently downgrades protection is not a recovery design.

## Platform limits

PRF requires runtime platform and authenticator support and can have a higher OS minimum than base passkey ceremonies. Check the generated [platform support matrix](../reference/platform-support.md) and test with the exact production provider and device mix.

The module's staged [artifact page](../reference/modules/webauthn-client-prf-crypto.md) contains a compile-checked end-to-end example.
