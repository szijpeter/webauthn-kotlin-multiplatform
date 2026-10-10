# webauthn-attestation-mds

Optional FIDO Metadata Service trust-source integration for attestation verification.

## What it provides

- `FidoMdsTrustSource`
- Metadata fetching and cache refresh workflow
- `TrustAnchorSource` implementation that can plug into attestation verification

## When to use

Use this when your backend wants attestation trust rooted in FIDO MDS metadata instead of only local trust anchors.

## How to use

<!-- doc-example: id=server-webauthn-attestation-mds-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/MdsExample.kt#mds-trust-source -->
```kotlin
import dev.webauthn.attestation.mds.FidoMdsTrustSource
import io.ktor.client.HttpClient

suspend fun buildTrustSource(
    httpClient: HttpClient,
    metadataUrl: String,
): FidoMdsTrustSource {
    val trustSource = FidoMdsTrustSource(
        httpClient = httpClient,
        metadataUrl = metadataUrl,
        nowEpochSeconds = { System.currentTimeMillis() / 1000 },
    )

    // Required first load: cache starts empty until an initial refresh.
    trustSource.refreshIfStale(maxAgeSeconds = 0)
    return trustSource
}
```

Real-world scenario: regulated environments can enforce attestation policy from fresh MDS metadata while keeping ceremony orchestration unchanged.

## How it fits

<!-- diagram: server-webauthn-attestation-mds-readme-1 -->
<a href="../../docs/diagrams/assets/server-webauthn-attestation-mds-readme-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-attestation-mds-readme-1-desktop-dark.svg">
  <img alt="attestation-mds · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/server-webauthn-attestation-mds-readme-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: attestation-mds · How it fits</summary>
<p>Phone view: <a href="../../docs/diagrams/assets/server-webauthn-attestation-mds-readme-1-mobile-light.svg">light</a> · <a href="../../docs/diagrams/assets/server-webauthn-attestation-mds-readme-1-mobile-dark.svg">dark</a>.</p>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: FIDO MDS endpoint; FidoMdsTrustSource cache; TrustAnchorSource contract; Attestation verifier; webauthn-server-core-jvm registration flow.</p>
<p>1. FIDO MDS endpoint → FidoMdsTrustSource cache.</p>
<p>2. FidoMdsTrustSource cache → TrustAnchorSource contract.</p>
<p>3. TrustAnchorSource contract → Attestation verifier.</p>
<p>4. Attestation verifier → webauthn-server-core-jvm registration flow.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- Initial refresh is mandatory before first use.
- Cache lifecycle and refresh policy are operational decisions you must own.
- This module is optional; attestation strategy stays deployment-specific.

## Status

Beta, optional trust-source module.
