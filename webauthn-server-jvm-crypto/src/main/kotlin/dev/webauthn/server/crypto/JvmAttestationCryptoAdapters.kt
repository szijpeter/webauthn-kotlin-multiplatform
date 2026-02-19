package dev.webauthn.server.crypto

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.cert.CertificateException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

internal data class CosePublicKeyMaterial(
    val kty: Long,
    val alg: Long? = null,
    val crv: Long? = null,
    val x: ByteArray? = null,
    val y: ByteArray? = null,
    val n: ByteArray? = null,
    val e: ByteArray? = null,
)

internal data class ParsedCertificate(
    val subjectDistinguishedName: String,
    val version: Int,
    val basicConstraints: Int,
    val extendedKeyUsageOids: List<String>,
    val criticalExtensionOids: Set<String>,
    val ecPublicKeyX: ByteArray? = null,
    val ecPublicKeyY: ByteArray? = null,
) {
    val isCa: Boolean
        get() = basicConstraints != -1
}

internal class JvmCertificateInspector {
    private val factory = CertificateFactory.getInstance("X.509")

    fun inspect(certificateDer: ByteArray): ParsedCertificate {
        val cert = factory.generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
        val ecPublicKey = cert.publicKey as? ECPublicKey
        val coordinateSizeBytes = ecPublicKey?.params?.curve?.field?.fieldSize?.let { (it + 7) / 8 }

        return ParsedCertificate(
            subjectDistinguishedName = cert.subjectX500Principal.name,
            version = cert.version,
            basicConstraints = cert.basicConstraints,
            extendedKeyUsageOids = cert.extendedKeyUsage ?: emptyList(),
            criticalExtensionOids = cert.criticalExtensionOIDs?.toSet() ?: emptySet(),
            ecPublicKeyX = ecPublicKey?.let {
                normalizeUnsignedCoordinate(it.w.affineX, coordinateSizeBytes ?: 32)
            },
            ecPublicKeyY = ecPublicKey?.let {
                normalizeUnsignedCoordinate(it.w.affineY, coordinateSizeBytes ?: 32)
            },
        )
    }

    fun extensionValue(certificateDer: ByteArray, oid: String): ByteArray? {
        val cert = factory.generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
        return cert.getExtensionValue(oid)
    }

    private fun normalizeUnsignedCoordinate(value: BigInteger, length: Int): ByteArray {
        val bytes = value.toByteArray()
        if (bytes.size == length) return bytes
        if (bytes.size == length + 1 && bytes.first() == 0.toByte()) {
            return bytes.copyOfRange(1, bytes.size)
        }
        if (bytes.size < length) {
            val padded = ByteArray(length)
            bytes.copyInto(padded, destinationOffset = length - bytes.size)
            return padded
        }
        return bytes.copyOfRange(bytes.size - length, bytes.size)
    }
}

internal class JvmCertificateChainValidator {
    private val factory = CertificateFactory.getInstance("X.509")

    fun verify(chainDer: List<ByteArray>, trustAnchorsDer: List<ByteArray>): Boolean {
        if (chainDer.isEmpty() || trustAnchorsDer.isEmpty()) {
            return false
        }

        val chain = chainDer.mapNotNull(::parseCertificate)
        if (chain.size != chainDer.size) {
            return false
        }

        val trustAnchors = trustAnchorsDer.mapNotNull(::parseCertificate)
            .map { TrustAnchor(it, null) }
            .toSet()
        if (trustAnchors.isEmpty()) {
            return false
        }

        return try {
            val certPath = factory.generateCertPath(chain)
            val params = PKIXParameters(trustAnchors).apply {
                isRevocationEnabled = false
            }
            CertPathValidator.getInstance("PKIX").validate(certPath, params)
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    fun verifySignedByNext(chainDer: List<ByteArray>): Boolean {
        if (chainDer.isEmpty()) {
            return false
        }
        val chain = chainDer.mapNotNull(::parseCertificate)
        if (chain.size != chainDer.size) {
            return false
        }

        return try {
            for (i in 0 until chain.size - 1) {
                chain[i].verify(chain[i + 1].publicKey)
            }
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun parseCertificate(certificateDer: ByteArray): X509Certificate? {
        return try {
            factory.generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
        } catch (_: CertificateException) {
            null
        } catch (_: ClassCastException) {
            null
        }
    }
}
