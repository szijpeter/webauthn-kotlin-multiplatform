package dev.webauthn.server.crypto

import dev.webauthn.crypto.CosePublicKeyMaterial

internal object CoseToSpkiConverter {

    fun convert(coseKey: ByteArray): ByteArray? {
        val material = parseCoseKey(coseKey) ?: return null
        return convert(material)
    }

    fun convert(material: CosePublicKeyMaterial): ByteArray? {
        return when (material.kty) {
            2L -> convertEc2(material)
            3L -> convertRsa(material)
            else -> null
        }
    }

    fun parseCoseKey(coseKey: ByteArray): CosePublicKeyMaterial? {
        val map = parseCoseMap(coseKey) ?: return null
        val kty = map[1L] as? Long ?: return null
        val alg = map[3L] as? Long
        
        // EC2 specific
        val crv = map[-1L] as? Long
        val x = map[-2L] as? ByteArray
        val y = map[-3L] as? ByteArray

        // RSA specific
        val n = map[-1L] as? ByteArray
        val e = map[-2L] as? ByteArray

        return CosePublicKeyMaterial(
            kty = kty,
            alg = alg,
            crv = crv,
            x = x,
            y = y,
            n = n,
            e = e
        )
    }

    private fun convertEc2(material: CosePublicKeyMaterial): ByteArray? {
        val crv = material.crv ?: return null
        val x = material.x ?: return null
        val y = material.y ?: return null

        if (crv != 1L) return null // Only P-256 supported for now

        // Uncompressed point: 0x04 || X || Y
        val point = byteArrayOf(0x04) + x + y
        
        // SPKI for EC: SEQUENCE { SEQUENCE { OID(id-ecPublicKey), OID(secp256r1) }, BIT STRING (point) }
        return derSequence(
            derSequence(
                derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)), // 1.2.840.10045.2.1
                derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07)) // 1.2.840.10045.3.1.7 (secp256r1)
            ),
            derBitString(point)
        )
    }

    private fun convertRsa(material: CosePublicKeyMaterial): ByteArray? {
        val n = material.n ?: return null
        val e = material.e ?: return null

        // RSA public key: SEQUENCE { INTEGER(n), INTEGER(e) }
        val rsaPubKey = derSequence(
            derInteger(n),
            derInteger(e)
        )

        // SPKI for RSA: SEQUENCE { SEQUENCE { OID(rsaEncryption), NULL }, BIT STRING (rsaPubKey) }
        return derSequence(
            derSequence(
                derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01)), // 1.2.840.113549.1.1.1
                derNull()
            ),
            derBitString(rsaPubKey)
        )
    }

    private fun parseCoseMap(bytes: ByteArray): Map<Long, Any>? {
        var offset = 0
        val header = readCborHeader(bytes, offset) ?: return null
        if (header.majorType != MAJOR_MAP || header.length == null) return null
        offset = header.nextOffset
        
        val result = mutableMapOf<Long, Any>()
        repeat(header.length.toInt()) {
            val keyResult = readCborInt(bytes, offset) ?: return null
            val key = keyResult.first
            offset = keyResult.second
            
            val valueHeader = readCborHeader(bytes, offset) ?: return null
            when (valueHeader.majorType) {
                MAJOR_UNSIGNED_INT, MAJOR_NEGATIVE_INT -> {
                    val v = readCborInt(bytes, offset) ?: return null
                    result[key] = v.first
                    offset = v.second
                }
                MAJOR_BYTE_STRING -> {
                    val v = readCborBytes(bytes, offset) ?: return null
                    result[key] = v.first
                    offset = v.second
                }
                else -> {
                    offset = skipCborItem(bytes, offset) ?: return null
                }
            }
        }
        return result
    }

    // ASN.1 helpers (mini version)
    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        val length = content.size
        val lengthBytes = if (length < 128) {
            byteArrayOf(length.toByte())
        } else if (length < 256) {
            byteArrayOf(0x81.toByte(), length.toByte())
        } else {
            byteArrayOf(0x82.toByte(), (length shr 8).toByte(), (length and 0xFF).toByte())
        }
        return byteArrayOf(tag.toByte()) + lengthBytes + content
    }

    private fun derSequence(vararg items: ByteArray) = derTag(0x30, items.reduce { acc, bytes -> acc + bytes })
    private fun derOid(oid: ByteArray) = derTag(0x06, oid)
    private fun derBitString(bits: ByteArray) = derTag(0x03, byteArrayOf(0x00) + bits)
    private fun derNull() = byteArrayOf(0x05, 0x00)
    
    private fun derInteger(value: ByteArray): ByteArray {
        // Handle positive integers (ensure no leading zeros unless necessary for MSB)
        var start = 0
        while (start < value.size - 1 && value[start] == 0.toByte()) start++
        
        return if (value[start].toInt() and 0x80 != 0) {
            // Negative signed integer, prepend 0x00 for unsigned representation
            derTag(0x02, byteArrayOf(0x00) + value.copyOfRange(start, value.size))
        } else {
            derTag(0x02, value.copyOfRange(start, value.size))
        }
    }
}
