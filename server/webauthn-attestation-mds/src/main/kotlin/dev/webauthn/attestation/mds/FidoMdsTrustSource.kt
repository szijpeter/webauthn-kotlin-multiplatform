package dev.webauthn.attestation.mds

import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Minimal representation of an MDS v3 metadata blob document.
 *
 * @property no Metadata statement sequence number.
 * @property nextUpdate RFC3339-like timestamp advertised by the blob.
 * @property entries Metadata entries carried by the blob.
 */
@Serializable
public data class MdsMetadataBlob(
    @SerialName("no") public val no: Long,
    @SerialName("nextUpdate") public val nextUpdate: String,
    @SerialName("entries") public val entries: List<MdsEntry>,
)

/**
 * MDS entry containing authenticator metadata and trust anchors.
 *
 * @property aaguid Optional AAGUID identifier from MDS metadata.
 * @property attestationRootCertificates PEM-encoded attestation roots.
 */
@Serializable
public data class MdsEntry(
    @SerialName("aaguid") public val aaguid: String? = null,
    @SerialName("attestationRootCertificates") public val attestationRootCertificates: List<String> = emptyList(),
)

/** Pull-based FIDO MDS trust source that maps AAGUIDs to attestation roots. */
public class FidoMdsTrustSource(
    private val httpClient: HttpClient,
    private val metadataUrl: String,
    private val nowEpochSeconds: () -> Long,
) : TrustAnchorSource {
    @Volatile
    private var cache: CachedBlob? = null

    override fun findTrustAnchors(aaguid: Aaguid?): List<Base64UrlBytes> {
        val snapshot = cache ?: return emptyList()
        val lookupAaguid = aaguid
            ?.bytes()
            ?.joinToString(separator = "") { byte -> "%02x".format(byte) }
        return snapshot.blob.entries
            .asSequence()
            .filter { entry ->
                lookupAaguid == null || normalizeAaguid(entry.aaguid) == lookupAaguid
            }
            .flatMap { it.attestationRootCertificates.asSequence() }
            .mapNotNull(::decodePemToDer)
            .map(Base64UrlBytes::fromBytes)
            .toList()
    }

    /**
     * Refreshes cached metadata when the cache age exceeds [maxAgeSeconds].
     */
    public suspend fun refreshIfStale(maxAgeSeconds: Long = 86_400) {
        val cached = cache
        if (cached != null) {
            val ageSeconds = nowEpochSeconds() - cached.fetchedAtEpochSeconds
            if (ageSeconds <= maxAgeSeconds) {
                return
            }
        }

        val blob: MdsMetadataBlob = httpClient.get(metadataUrl).body()
        cache = CachedBlob(blob = blob, fetchedAtEpochSeconds = nowEpochSeconds())
    }
}

private data class CachedBlob(
    val blob: MdsMetadataBlob,
    val fetchedAtEpochSeconds: Long,
)

private fun normalizeAaguid(value: String?): String? = value?.replace("-", "")?.lowercase()

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
