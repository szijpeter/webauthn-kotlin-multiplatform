package dev.webauthn.server.crypto

import java.security.KeyPair
import java.security.PrivateKey
import java.security.Signature

internal object TestCertificateFixtures {
    private val oidCommonName = byteArrayOf(0x55, 0x04, 0x03) // 2.5.4.3
    private val oidSha256WithEcdsa = byteArrayOf(
        0x2A,
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x04,
        0x03,
        0x02,
    ) // 1.2.840.10045.4.3.2
    private val oidSha256WithRsa = byteArrayOf(
        0x2A,
        0x86.toByte(),
        0x48,
        0x86.toByte(),
        0xF7.toByte(),
        0x0D,
        0x01,
        0x01,
        0x0B,
    ) // 1.2.840.113549.1.1.11

    fun selfSignedEcCertificate(
        keyPair: KeyPair,
        subjectCn: String = "EC Test",
        extensions: List<ByteArray> = emptyList(),
    ): ByteArray {
        return certificate(
            issuerCn = subjectCn,
            subjectCn = subjectCn,
            subjectPublicKeyInfo = keyPair.public.encoded,
            signerPrivateKey = keyPair.private,
            signingAlgorithm = "SHA256withECDSA",
            signingOid = oidSha256WithEcdsa,
            extensions = extensions,
        )
    }

    fun selfSignedRsaCertificate(
        keyPair: KeyPair,
        subjectCn: String = "RSA Test",
    ): ByteArray {
        return certificate(
            issuerCn = subjectCn,
            subjectCn = subjectCn,
            subjectPublicKeyInfo = keyPair.public.encoded,
            signerPrivateKey = keyPair.private,
            signingAlgorithm = "SHA256withRSA",
            signingOid = oidSha256WithRsa,
        )
    }

    fun issuedRsaCertificate(
        issuerCn: String,
        subjectCn: String,
        subjectPublicKeyInfo: ByteArray,
        issuerPrivateKey: PrivateKey,
    ): ByteArray {
        return certificate(
            issuerCn = issuerCn,
            subjectCn = subjectCn,
            subjectPublicKeyInfo = subjectPublicKeyInfo,
            signerPrivateKey = issuerPrivateKey,
            signingAlgorithm = "SHA256withRSA",
            signingOid = oidSha256WithRsa,
        )
    }

    fun aaguidExtension(aaguid: ByteArray): ByteArray {
        val aaguidOid = byteArrayOf(
            0x2B,
            0x06,
            0x01,
            0x04,
            0x01,
            0x82.toByte(),
            0xE5.toByte(),
            0x1C,
            0x01,
            0x01,
            0x04,
        ) // 1.3.6.1.4.1.45724.1.1.4
        val extValue = derOctetString(aaguid)
        return derSequence(derOid(aaguidOid), derOctetString(extValue))
    }

    private fun certificate(
        issuerCn: String,
        subjectCn: String,
        subjectPublicKeyInfo: ByteArray,
        signerPrivateKey: PrivateKey,
        signingAlgorithm: String,
        signingOid: ByteArray,
        extensions: List<ByteArray> = emptyList(),
    ): ByteArray {
        val issuer = rdnSequence(issuerCn)
        val subject = rdnSequence(subjectCn)
        val sigAlgId = derSequence(derOid(signingOid))
        val tbsParts = mutableListOf(
            derExplicit(0, derInteger(byteArrayOf(0x02))), // v3
            derInteger(byteArrayOf(0x01)),
            sigAlgId,
            issuer,
            derSequence(derUtcTime("250101000000Z"), derUtcTime("350101000000Z")),
            subject,
            derRaw(subjectPublicKeyInfo),
        )
        if (extensions.isNotEmpty()) {
            tbsParts.add(derExplicit(3, derSequence(*extensions.toTypedArray())))
        }
        val tbs = derSequence(*tbsParts.toTypedArray())

        val signature = Signature.getInstance(signingAlgorithm).run {
            initSign(signerPrivateKey)
            update(tbs)
            sign()
        }

        return derSequence(
            derRaw(tbs),
            sigAlgId,
            derBitString(signature),
        )
    }

    private fun rdnSequence(cn: String): ByteArray {
        return derSequence(
            derSet(
                derSequence(
                    derOid(oidCommonName),
                    derUtf8String(cn),
                ),
            ),
        )
    }

    private fun derSequence(vararg items: ByteArray): ByteArray = derTag(0x30, concat(*items))
    private fun derSet(vararg items: ByteArray): ByteArray = derTag(0x31, concat(*items))
    private fun derInteger(value: ByteArray): ByteArray = derTag(0x02, value)
    private fun derOctetString(value: ByteArray): ByteArray = derTag(0x04, value)
    private fun derBitString(value: ByteArray): ByteArray = derTag(0x03, concat(byteArrayOf(0x00), value))
    private fun derOid(encoded: ByteArray): ByteArray = derTag(0x06, encoded)
    private fun derUtf8String(value: String): ByteArray = derTag(0x0C, value.encodeToByteArray())
    private fun derUtcTime(value: String): ByteArray = derTag(0x17, value.encodeToByteArray())
    private fun derExplicit(tag: Int, content: ByteArray): ByteArray = derTag(0xA0 or tag, content)
    private fun derRaw(content: ByteArray): ByteArray = content

    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        return concat(byteArrayOf(tag.toByte()), derLength(content.size), content)
    }

    private fun derLength(length: Int): ByteArray {
        return when {
            length < 128 -> byteArrayOf(length.toByte())
            length < 256 -> byteArrayOf(0x81.toByte(), length.toByte())
            else -> byteArrayOf(
                0x82.toByte(),
                (length shr 8).toByte(),
                (length and 0xFF).toByte(),
            )
        }
    }

    private fun concat(vararg chunks: ByteArray): ByteArray {
        val size = chunks.sumOf { it.size }
        val out = ByteArray(size)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(out, destinationOffset = offset)
            offset += chunk.size
        }
        return out
    }
}
