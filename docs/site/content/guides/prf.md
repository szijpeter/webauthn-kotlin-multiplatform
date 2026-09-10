# PRF application crypto

The PRF extension can derive stable credential-bound output during an authentication ceremony. The optional `webauthn-client-prf-crypto` module turns that output into a short-lived AES-256 key session through HKDF-SHA256 and provides AES-GCM helpers.

## Ownership model

<!-- diagram: public-prf-ownership-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-prf-ownership-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../../diagrams/assets/public-prf-ownership-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-prf-ownership-1-desktop-dark.svg">
  <img alt="PRF ownership. Local key derivation and server authentication have separate responsibilities." src="../../../diagrams/assets/public-prf-ownership-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: PRF ownership</summary>
<p>Local key derivation and server authentication have separate responsibilities.</p>
<p>Nodes: App-persisted salt; Passkey assertion with PRF; Credential-bound PRF output; HKDF with stable context; Short-lived crypto session; AES-GCM ciphertext package; Explicit key clear; App-owned durable storage.</p>
<p>1. App-persisted salt → Passkey assertion with PRF.</p>
<p>2. Passkey assertion with PRF → Credential-bound PRF output.</p>
<p>3. Credential-bound PRF output → HKDF with stable context.</p>
<p>4. HKDF with stable context → Short-lived crypto session.</p>
<p>5. Short-lived crypto session → AES-GCM ciphertext package.</p>
<p>6. Short-lived crypto session → Explicit key clear.</p>
<p>7. AES-GCM ciphertext package → App-owned durable storage.</p>
</details>
<!-- /diagram -->

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
