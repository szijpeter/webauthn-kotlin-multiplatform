package dev.webauthn.documentation.examples

// docs-region mds-trust-source
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
// docs-endregion mds-trust-source
