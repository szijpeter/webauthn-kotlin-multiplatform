package dev.webauthn.server.crypto

import dev.webauthn.crypto.TrustAnchorSource
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

public class ResourceTrustAnchorSource : TrustAnchorSource {

    private val trustedCerts: List<ByteArray> by lazy {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = mutableListOf<ByteArray>()

        val filenames = listOf(
            "Apple_WebAuthn_Root_CA.pem",
            "Google_Hardware_Attestation_Root_1.pem",
            "Google_Hardware_Attestation_Root_2.pem"
        )

        for (filename in filenames) {
            val path = "dev/webauthn/server/crypto/roots/$filename"
            val stream: InputStream? = javaClass.classLoader.getResourceAsStream(path)
            if (stream != null) {
                stream.use {
                    try {
                        // CertificateFactory can handle PEM if it has headers
                        // It can also handle multiple certs in one stream
                        val generatedCerts = factory.generateCertificates(it)
                        for (cert in generatedCerts) {
                            if (cert is X509Certificate) {
                                certs.add(cert.encoded)
                            }
                        }
                    } catch (e: Exception) {
                        System.err.println("Failed to load trust anchor: $filename - ${e.message}")
                    }
                }
            } else {
                System.err.println("Trust anchor resource not found: $path")
            }
        }
        certs
    }

    override fun findTrustAnchors(aaguid: ByteArray?): List<ByteArray> {
        // Return all trusted roots.
        // In a more advanced implementation, we could filter by AAGUID if we had a mapping.
        return trustedCerts
    }
}
