package dev.webauthn.server.crypto

import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

internal class StaticTrustAnchorSource(
    private val certificates: List<X509Certificate>,
) : TrustAnchorSource {
    private val encodedCertificates: List<Base64UrlBytes> =
        certificates.map { Base64UrlBytes.fromBytes(it.encoded) }

    override fun findTrustAnchors(aaguid: Aaguid?): List<Base64UrlBytes> {
        return encodedCertificates
    }

    companion object {
        fun fromResourcePath(path: String): StaticTrustAnchorSource {
            val stream = StaticTrustAnchorSource::class.java.getResourceAsStream(path)
                ?: throw IllegalArgumentException("Resource not found: $path")
            return fromStream(stream)
        }

        fun fromStream(stream: InputStream): StaticTrustAnchorSource {
            stream.use {
                val factory = CertificateFactory.getInstance("X.509")
                val certs = factory.generateCertificates(it)
                return StaticTrustAnchorSource(certs.filterIsInstance<X509Certificate>())
            }
        }
    }
}
