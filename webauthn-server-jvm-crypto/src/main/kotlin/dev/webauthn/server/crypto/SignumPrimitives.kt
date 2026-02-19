package dev.webauthn.server.crypto

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.sign.verifierFor
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.coseAlgorithmFromCode
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

internal object SignumPrimitives {
    fun sha256(input: ByteArray): ByteArray = Digest.SHA256.digest(input)

    fun decodeCoseMaterial(coseKey: ByteArray): CosePublicKeyMaterial? {
        val decoded = CoseKey.deserialize(coseKey).getOrNull() ?: return null
        val publicKey = decoded.toCryptoPublicKey().getOrNull() ?: return null
        val alg = decoded.algorithm?.coseValue?.toLong()

        return when (decoded.type) {
            CoseKeyType.EC2 -> {
                val ecKey = publicKey as? CryptoPublicKey.EC ?: return null
                CosePublicKeyMaterial(
                    kty = 2L,
                    alg = alg,
                    crv = ecCurveToCoseCurve(ecKey.curve),
                    x = ecKey.xBytes,
                    y = ecKey.yBytes,
                )
            }

            CoseKeyType.RSA -> {
                val rsaKey = publicKey as? CryptoPublicKey.RSA ?: return null
                CosePublicKeyMaterial(
                    kty = 3L,
                    alg = alg,
                    n = rsaKey.n.magnitude,
                    e = rsaKey.e.magnitude,
                )
            }

            else -> null
        }
    }

    fun decodeCosePublicKey(coseKey: ByteArray): CryptoPublicKey? =
        CoseKey.deserialize(coseKey).getOrNull()?.toCryptoPublicKey()?.getOrNull()

    fun toSubjectPublicKeyInfo(material: CosePublicKeyMaterial): ByteArray? {
        return when (material.kty) {
            2L -> {
                val curve = coseCurveToEcCurve(material.crv ?: return null) ?: return null
                val x = material.x ?: return null
                val y = material.y ?: return null
                try {
                    CryptoPublicKey.EC.fromUncompressed(curve, x, y).encodeToDer()
                } catch (_: IllegalArgumentException) {
                    null
                } catch (_: Asn1Exception) {
                    null
                }
            }

            3L -> {
                val n = material.n ?: return null
                val e = material.e ?: return null
                try {
                    CryptoPublicKey.RSA(
                        n = Asn1Integer.fromUnsignedByteArray(n),
                        e = Asn1Integer.fromUnsignedByteArray(e),
                    ).encodeToDer()
                } catch (_: IllegalArgumentException) {
                    null
                } catch (_: Asn1Exception) {
                    null
                }
            }

            else -> null
        }
    }

    fun toUncompressedEcPoint(material: CosePublicKeyMaterial): ByteArray? {
        val x = material.x ?: return null
        val y = material.y ?: return null
        return byteArrayOf(0x04) + x + y
    }

    fun coseAlgorithmFromMaterial(material: CosePublicKeyMaterial): CoseAlgorithm? {
        val algCode = material.alg?.toInt() ?: return null
        return coseAlgorithmFromCode(algCode)
    }

    fun verifyWithCosePublicKey(
        algorithm: CoseAlgorithm,
        publicKeyCose: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val publicKey = decodeCosePublicKey(publicKeyCose) ?: return false
        return verifyWithPublicKey(algorithm, publicKey, data, signature)
    }

    fun verifyWithCertificate(
        algorithm: CoseAlgorithm,
        certificateDer: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val publicKey = decodeCertificatePublicKey(certificateDer) ?: return false
        return verifyWithPublicKey(algorithm, publicKey, data, signature)
    }

    fun parseCertificate(certificateDer: ByteArray): X509Certificate? = try {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
    } catch (_: CertificateException) {
        null
    } catch (_: ClassCastException) {
        null
    }

    private fun decodeCertificatePublicKey(certificateDer: ByteArray): CryptoPublicKey? {
        val cert = parseCertificate(certificateDer) ?: return null
        return cert.publicKey.toCryptoPublicKey().getOrNull()
    }

    private fun verifyWithPublicKey(
        algorithm: CoseAlgorithm,
        publicKey: CryptoPublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val signumAlgorithm = toSignumAlgorithm(algorithm) ?: return false
        val verifier = signumAlgorithm.verifierFor(publicKey).getOrNull() ?: return false
        val cryptoSignature = parseSignature(algorithm, signature) ?: return false
        return verifier.verify(data, cryptoSignature).isSuccess
    }

    private fun toSignumAlgorithm(algorithm: CoseAlgorithm): SignatureAlgorithm? =
        when (algorithm) {
            CoseAlgorithm.ES256 -> SignatureAlgorithm.ECDSAwithSHA256
            CoseAlgorithm.RS256 -> SignatureAlgorithm.RSAwithSHA256andPKCS1Padding
            CoseAlgorithm.EdDSA -> null
        }

    private fun parseSignature(algorithm: CoseAlgorithm, signature: ByteArray): CryptoSignature? =
        when (algorithm) {
            CoseAlgorithm.ES256 -> try {
                CryptoSignature.EC.decodeFromDer(signature)
            } catch (_: IllegalArgumentException) {
                null
            } catch (_: Asn1Exception) {
                null
            }
            CoseAlgorithm.RS256 -> CryptoSignature.RSA(signature)
            CoseAlgorithm.EdDSA -> null
        }

    private fun ecCurveToCoseCurve(curve: ECCurve): Long =
        when (curve) {
            ECCurve.SECP_256_R_1 -> 1L
            ECCurve.SECP_384_R_1 -> 2L
            ECCurve.SECP_521_R_1 -> 3L
        }

    private fun coseCurveToEcCurve(curve: Long): ECCurve? =
        when (curve) {
            1L -> ECCurve.SECP_256_R_1
            2L -> ECCurve.SECP_384_R_1
            3L -> ECCurve.SECP_521_R_1
            else -> null
        }
}
