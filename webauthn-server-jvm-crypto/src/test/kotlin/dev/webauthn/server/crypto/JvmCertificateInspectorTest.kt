package dev.webauthn.server.crypto

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JvmCertificateInspectorTest {
    private val inspector = JvmCertificateInspector()

    @Test
    fun inspectsEcCertificateMetadata() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val cert = TestCertificateFixtures.selfSignedEcCertificate(keyPair, subjectCn = "Inspector Test")

        val parsed = inspector.inspect(cert)
        assertTrue(parsed.subjectDistinguishedName.contains("CN=Inspector Test"))
        assertEquals(3, parsed.version)
        assertFalse(parsed.isCa)
        val ecX = assertNotNull(parsed.ecPublicKeyX)
        val ecY = assertNotNull(parsed.ecPublicKeyY)
        assertEquals(32, ecX.size)
        assertEquals(32, ecY.size)
    }

    @Test
    fun returnsExtensionValueByOid() {
        val aaguid = ByteArray(16) { (it + 1).toByte() }
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val cert = TestCertificateFixtures.selfSignedEcCertificate(
            keyPair = keyPair,
            extensions = listOf(TestCertificateFixtures.aaguidExtension(aaguid)),
        )

        val rawExtension = inspector.extensionValue(cert, "1.3.6.1.4.1.45724.1.1.4")
        assertNotNull(rawExtension)

        val parsed = DerParser(rawExtension).readOctetString()
        val maybeInner = runCatching { DerParser(parsed).readOctetString() }.getOrNull()
        if (maybeInner != null) {
            assertContentEquals(aaguid, maybeInner)
        } else {
            assertContentEquals(aaguid, parsed)
        }
    }
}
