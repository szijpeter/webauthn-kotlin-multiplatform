# webauthn-crypto-api

Contract layer for cryptographic and trust operations used by validation and ceremony services.

## What it provides

- `RpIdHasher`, `SignatureVerifier`, `AttestationVerifier`, `TrustAnchorSource` contracts
- A vendor-neutral seam between validation/orchestration and concrete crypto backends
- A stable place to plug your own cryptography or trust policy implementation

## When to use

- You are implementing custom crypto or attestation behavior.
- You want server logic to depend on interfaces, not provider details.
- You are building an alternative to `webauthn-server-jvm-crypto`.

## How to use

<!-- doc-example: id=core-webauthn-crypto-api-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/CryptoExample.kt#crypto-rp-id-hasher -->
```kotlin
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.model.RpIdHash

fun rpIdHasher(sha256: (ByteArray) -> ByteArray): RpIdHasher {
    return RpIdHasher { rpId ->
        val rpIdSha256 = sha256(rpId.encodeToByteArray())
        RpIdHash.fromBytes(rpIdSha256)
    }
}
```

Real-world scenario: multi-tenant backends can swap verifier and trust-anchor strategy per tenant while keeping ceremony services unchanged.

## How it fits

<!-- diagram: core-webauthn-crypto-api-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-crypto-api-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/core-webauthn-crypto-api-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/core-webauthn-crypto-api-readme-1-desktop-dark.svg">
  <img alt="crypto-api · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/core-webauthn-crypto-api-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: crypto-api · How it fits</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-core; webauthn-crypto-api contracts; webauthn-server-core-jvm; webauthn-server-jvm-crypto; webauthn-attestation-mds.</p>
<p>1. webauthn-core → webauthn-crypto-api contracts.</p>
<p>2. webauthn-server-core-jvm → webauthn-crypto-api contracts.</p>
<p>3. webauthn-server-jvm-crypto → webauthn-crypto-api contracts.</p>
<p>4. webauthn-attestation-mds → webauthn-crypto-api contracts.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- Contract ownership stays here; concrete security posture is in your implementation.
- Incorrect hashing, signature-verification, or trust-anchor implementations weaken validation guarantees.
- Kotlin consumers that enable `-Xreturn-value-checker=check` are warned when crypto or trust results are ignored.

## Status

Beta, vendor-agnostic contract layer.
