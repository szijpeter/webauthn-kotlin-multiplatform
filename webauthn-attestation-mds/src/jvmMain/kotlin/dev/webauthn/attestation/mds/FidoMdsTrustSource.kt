package dev.webauthn.attestation.mds

import dev.webauthn.crypto.TrustAnchorSource
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
public data class MdsMetadataBlob(
    @SerialName("no") public val no: Long,
    @SerialName("nextUpdate") public val nextUpdate: String,
    @SerialName("entries") public val entries: List<MdsEntry>,
)

@Serializable
public data class MdsEntry(
    @SerialName("aaguid") public val aaguid: String? = null,
    @SerialName("attestationRootCertificates") public val attestationRootCertificates: List<String> = emptyList(),
)

public class FidoMdsTrustSource(
    private val httpClient: HttpClient,
    private val metadataUrl: String,
    private val now: () -> Instant,
) : TrustAnchorSource {
    @Volatile
    private var cache: CachedBlob? = null

    override fun findTrustAnchors(aaguid: ByteArray?): List<ByteArray> {
        val snapshot = cache ?: return emptyList()
        val lookupAaguid = aaguid?.joinToString(separator = "") { byte -> "%02x".format(byte) }
        return snapshot.blob.entries
            .asSequence()
            .filter { lookupAaguid == null || it.aaguid.equals(lookupAaguid, ignoreCase = true) }
            .flatMap { it.attestationRootCertificates.asSequence() }
            .mapNotNull(::decodePemToDer)
            .toList()
    }

    public suspend fun refreshIfStale(maxAgeSeconds: Long = 86_400) {
        val cached = cache
        if (cached != null) {
            val ageSeconds = now().epochSeconds - cached.fetchedAt.epochSeconds
            if (ageSeconds <= maxAgeSeconds) {
                return
            }
        }

        val blob: MdsMetadataBlob = httpClient.get(metadataUrl).body()
        cache = CachedBlob(blob = blob, fetchedAt = now())
    }
}

private data class CachedBlob(
    val blob: MdsMetadataBlob,
    val fetchedAt: Instant,
)

private fun decodePemToDer(value: String): ByteArray? {
    return try {
        val normalized = value
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")
        java.util.Base64.getDecoder().decode(normalized)
    } catch (_: IllegalArgumentException) {
        null
    }
}
