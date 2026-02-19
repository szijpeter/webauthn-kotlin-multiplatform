package dev.webauthn.server.crypto

import at.asitplus.KmmResult
import at.asitplus.catching
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

    fun decodeCoseMaterial(coseKey: ByteArray): CosePublicKeyMaterial? =
        decodeCoseMaterialResult(coseKey).getOrNull()

    fun decodeCosePublicKey(coseKey: ByteArray): CryptoPublicKey? =
        decodeCosePublicKeyResult(coseKey).getOrNull()

    fun toSubjectPublicKeyInfo(material: CosePublicKeyMaterial): ByteArray? =
        toSubjectPublicKeyInfoResult(material).getOrNull()

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

    fun parseCertificate(certificateDer: ByteArray): X509Certificate? =
        parseCertificateResult(certificateDer).getOrNull()

    private fun decodeCertificatePublicKey(certificateDer: ByteArray): CryptoPublicKey? {
        val cert = parseCertificate(certificateDer) ?: return null
        return cert.publicKey.toCryptoPublicKey().getOrNull()
    }

    private fun verifyWithPublicKey(
        algorithm: CoseAlgorithm,
        publicKey: CryptoPublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean = verifyWithPublicKeyResult(algorithm, publicKey, data, signature).isSuccess

    private fun toSignumAlgorithm(algorithm: CoseAlgorithm): SignatureAlgorithm? =
        when (algorithm) {
            CoseAlgorithm.ES256 -> SignatureAlgorithm.ECDSAwithSHA256
            CoseAlgorithm.RS256 -> SignatureAlgorithm.RSAwithSHA256andPKCS1Padding
            CoseAlgorithm.EdDSA -> null
        }

    private fun decodeCoseMaterialResult(coseKey: ByteArray): KmmResult<CosePublicKeyMaterial> =
        CoseKey.deserialize(coseKey).transform { decoded ->
            decoded.toCryptoPublicKey().transform { publicKey ->
                toCoseMaterialResult(
                    keyType = decoded.type,
                    algorithm = decoded.algorithm?.coseValue?.toLong(),
                    publicKey = publicKey,
                )
            }
        }

    private fun decodeCosePublicKeyResult(coseKey: ByteArray): KmmResult<CryptoPublicKey> =
        CoseKey.deserialize(coseKey).transform { it.toCryptoPublicKey() }

    private fun toCoseMaterialResult(
        keyType: CoseKeyType,
        algorithm: Long?,
        publicKey: CryptoPublicKey,
    ): KmmResult<CosePublicKeyMaterial> =
        when (keyType) {
            CoseKeyType.EC2 -> {
                val ecKey = publicKey as? CryptoPublicKey.EC
                    ?: return failureResult("COSE EC2 key could not be decoded as an EC public key")
                KmmResult(
                    CosePublicKeyMaterial(
                        kty = 2L,
                        alg = algorithm,
                        crv = ecCurveToCoseCurve(ecKey.curve),
                        x = ecKey.xBytes,
                        y = ecKey.yBytes,
                    ),
                )
            }

            CoseKeyType.RSA -> {
                val rsaKey = publicKey as? CryptoPublicKey.RSA
                    ?: return failureResult("COSE RSA key could not be decoded as an RSA public key")
                KmmResult(
                    CosePublicKeyMaterial(
                        kty = 3L,
                        alg = algorithm,
                        n = rsaKey.n.magnitude,
                        e = rsaKey.e.magnitude,
                    ),
                )
            }

            else -> failureResult("Unsupported COSE key type: $keyType")
        }

    private fun toSubjectPublicKeyInfoResult(material: CosePublicKeyMaterial): KmmResult<ByteArray> =
        when (material.kty) {
            2L -> {
                val curve = coseCurveToEcCurve(material.crv ?: return failureResult("EC COSE key is missing curve id"))
                    ?: return failureResult("Unsupported EC curve id: ${material.crv}")
                val x = material.x ?: return failureResult("EC COSE key is missing x-coordinate")
                val y = material.y ?: return failureResult("EC COSE key is missing y-coordinate")
                catchingAsn1OrIllegalArgument {
                    CryptoPublicKey.EC.fromUncompressed(curve, x, y).encodeToDer()
                }
            }

            3L -> {
                val n = material.n ?: return failureResult("RSA COSE key is missing modulus")
                val e = material.e ?: return failureResult("RSA COSE key is missing exponent")
                catchingAsn1OrIllegalArgument {
                    CryptoPublicKey.RSA(
                        n = Asn1Integer.fromUnsignedByteArray(n),
                        e = Asn1Integer.fromUnsignedByteArray(e),
                    ).encodeToDer()
                }
            }

            else -> failureResult("Unsupported COSE key type: ${material.kty}")
        }

    private fun parseCertificateResult(certificateDer: ByteArray): KmmResult<X509Certificate> =
        catchingCertificateParse {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
        }

    private fun verifyWithPublicKeyResult(
        algorithm: CoseAlgorithm,
        publicKey: CryptoPublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): KmmResult<*> {
        val signumAlgorithm = toSignumAlgorithm(algorithm)
            ?: return failureResult<Any?>("Unsupported COSE algorithm: $algorithm")

        return signumAlgorithm.verifierFor(publicKey).transform { verifier ->
            parseSignatureResult(algorithm, signature).transform { cryptoSignature ->
                verifier.verify(data, cryptoSignature)
            }
        }
    }

    private fun parseSignatureResult(algorithm: CoseAlgorithm, signature: ByteArray): KmmResult<CryptoSignature> =
        when (algorithm) {
            CoseAlgorithm.ES256 -> catchingAsn1OrIllegalArgument {
                CryptoSignature.EC.decodeFromDer(signature)
            }
            CoseAlgorithm.RS256 -> KmmResult(CryptoSignature.RSA(signature))
            CoseAlgorithm.EdDSA -> failureResult("Unsupported COSE algorithm: $algorithm")
        }

    private inline fun <T> catchingAsn1OrIllegalArgument(block: () -> T): KmmResult<T> =
        catching(block).mapFailure(::expectAsn1OrIllegalArgument)

    private inline fun <T> catchingCertificateParse(block: () -> T): KmmResult<T> =
        catching(block).mapFailure(::expectCertificateParseFailure)

    private fun expectAsn1OrIllegalArgument(throwable: Throwable): Throwable =
        when (throwable) {
            is Asn1Exception,
            is IllegalArgumentException -> throwable
            else -> throw throwable
        }

    private fun expectCertificateParseFailure(throwable: Throwable): Throwable =
        when (throwable) {
            is CertificateException,
            is ClassCastException -> throwable
            else -> throw throwable
        }

    private fun <T> failureResult(message: String): KmmResult<T> =
        KmmResult(IllegalArgumentException(message))

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
