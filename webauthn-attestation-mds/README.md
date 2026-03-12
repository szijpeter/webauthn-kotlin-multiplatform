# webauthn-attestation-mds

Audience: backends that want optional FIDO Metadata Service trust anchors for attestation verification.

Use this module when you want to fetch and cache MDS metadata, then expose trust anchors through `TrustAnchorSource`.

```kotlin
import dev.webauthn.attestation.mds.FidoMdsTrustSource

suspend fun buildTrustSource(): FidoMdsTrustSource {
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

Choose this when attestation trust needs to be driven by FIDO MDS rather than only local trust-anchor resources.

Status: beta, optional trust-source module.
