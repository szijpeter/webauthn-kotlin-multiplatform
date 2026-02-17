package dev.webauthn.server.crypto

import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyMaterial
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.ParsedCertificate
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

public class JvmDigestService : DigestService {
    override fun sha256(input: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(input)
    }
}

public class JvmCosePublicKeyDecoder : CosePublicKeyDecoder {
    override fun decode(coseKey: ByteArray): CosePublicKeyMaterial? {
        return CoseToSpkiConverter.parseCoseKey(coseKey)
    }
}

public class JvmCosePublicKeyNormalizer : CosePublicKeyNormalizer {
    override fun toSubjectPublicKeyInfo(material: CosePublicKeyMaterial): ByteArray? {
        return CoseToSpkiConverter.convert(material)
    }

    override fun toUncompressedEcPoint(material: CosePublicKeyMaterial): ByteArray? {
        val x = material.x ?: return null
        val y = material.y ?: return null
        return byteArrayOf(0x04) + x + y
    }
}

public class JvmCertificateSignatureVerifier : CertificateSignatureVerifier {
    private val factory = CertificateFactory.getInstance("X.509")

    override fun verify(
        algorithm: CoseAlgorithm,
        certificateDer: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val cert = parseCertificate(certificateDer) ?: return false
        val jcaAlgorithm = JcaAlgorithmMapper.signatureAlgorithm(algorithm)

        return try {
            val verifier = Signature.getInstance(jcaAlgorithm)
            verifier.initVerify(cert.publicKey)
            verifier.update(data)
            verifier.verify(signature)
        } catch (_: Exception) {
            false
        }
    }

    private fun parseCertificate(certificateDer: ByteArray): X509Certificate? {
        return try {
            factory.generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
        } catch (_: Exception) {
            null
        }
    }
}

public class JvmCertificateInspector : CertificateInspector {
    private val factory = CertificateFactory.getInstance("X.509")

    override fun inspect(certificateDer: ByteArray): ParsedCertificate {
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

    override fun extensionValue(certificateDer: ByteArray, oid: String): ByteArray? {
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

public class JvmCertificateChainValidator : CertificateChainValidator {
    private val factory = CertificateFactory.getInstance("X.509")

    override fun verify(chainDer: List<ByteArray>, trustAnchorsDer: List<ByteArray>): Boolean {
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
        } catch (_: Exception) {
            false
        }
    }

    override fun verifySignedByNext(chainDer: List<ByteArray>): Boolean {
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
        } catch (_: Exception) {
            false
        }
    }

    private fun parseCertificate(certificateDer: ByteArray): X509Certificate? {
        return try {
            factory.generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
        } catch (_: Exception) {
            null
        }
    }
}
