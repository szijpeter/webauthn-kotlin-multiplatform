package dev.webauthn.server.crypto

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResourceTrustAnchorSourceTest {
    @Test
    fun bundledTrustAnchorsLoadAsX509Certificates() {
        val source = ResourceTrustAnchorSource()
        val trustAnchors = source.findTrustAnchors(aaguid = null)

        assertEquals(3, trustAnchors.size, "Expected bundled Apple + Google trust anchors")

        val factory = CertificateFactory.getInstance("X.509")
        trustAnchors.forEachIndexed { index, der ->
            val certificate = factory.generateCertificate(ByteArrayInputStream(der))
            assertTrue(certificate is X509Certificate, "Expected X.509 trust anchor at index $index")
        }
    }
}
