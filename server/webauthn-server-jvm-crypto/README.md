# webauthn-server-jvm-crypto

Default JVM crypto backend for the server stack.

## What it provides

- `JvmRpIdHasher`
- `JvmSignatureVerifier`
- `StrictAttestationVerifier`
- Signum-first implementation choices for hashing/signature/attestation paths

## When to use

Use this when you want tested JVM defaults instead of implementing `webauthn-crypto-api` yourself.

## How to use

<!-- doc-example: id=server-webauthn-server-jvm-crypto-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/ServerCryptoExample.kt#server-jvm-crypto -->
```kotlin
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier

/** Default JVM cryptographic dependencies for server ceremonies. */
data class ServerCrypto(
    val rpIdHasher: RpIdHasher,
    val signatureVerifier: SignatureVerifier,
    val attestationVerifier: AttestationVerifier,
)

fun serverCrypto(): ServerCrypto {
    val rpIdHasher = JvmRpIdHasher()
    val signatureVerifier = JvmSignatureVerifier()
    val attestationVerifier = StrictAttestationVerifier(signatureVerifier = signatureVerifier)
    return ServerCrypto(rpIdHasher, signatureVerifier, attestationVerifier)
}
```

Real-world scenario: wire these defaults into `RegistrationService` and `AuthenticationService` so your backend can verify assertions immediately without custom crypto plumbing.

## How it fits

<!-- diagram: server-webauthn-server-jvm-crypto-readme-1 -->
<a href="../../docs/diagrams/assets/server-webauthn-server-jvm-crypto-readme-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-server-jvm-crypto-readme-1-desktop-dark.svg">
  <img alt="server-jvm-crypto · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/server-webauthn-server-jvm-crypto-readme-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: server-jvm-crypto · How it fits</summary>
<p>Phone view: <a href="../../docs/diagrams/assets/server-webauthn-server-jvm-crypto-readme-1-mobile-light.svg">light</a> · <a href="../../docs/diagrams/assets/server-webauthn-server-jvm-crypto-readme-1-mobile-dark.svg">dark</a>.</p>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-server-core-jvm; webauthn-server-jvm-crypto; webauthn-crypto-api; webauthn-attestation-mds (optional).</p>
<p>1. webauthn-server-core-jvm → webauthn-server-jvm-crypto.</p>
<p>2. webauthn-server-jvm-crypto → webauthn-crypto-api.</p>
<p>3. webauthn-attestation-mds (optional) → webauthn-crypto-api.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- This module is JVM-specific and not a multiplatform crypto abstraction.
- Attestation CBOR parsing depends on shared strict scanner primitives from `webauthn-cbor-core`.
- If you need non-default trust policy, compose with custom `TrustAnchorSource` or verifier implementations.

## Status

Beta, Signum-first JVM backend crypto.
