package dev.webauthn.server.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import java.util.Base64

class CoseConformanceTest {

    @Test
    fun testEc2KeyConversion() {
        // Example EC2 key (P-256)
        // COSE Key:
        // 1 (kty) : 2 (EC2)
        // 3 (alg) : -7 (ES256)
        // -1 (crv) : 1 (P-256)
        // -2 (x) : ...
        // -3 (y) : ...
        
        val x = hexToBytes("5A2C597405202641026040854298132646635201081389279585640728956973")
        val y = hexToBytes("9871348419688404874312689252327591605332849202029304670058814521")
        
        // Construct COSE map
        // map(5) { 1:2, 3:-7, -1:1, -2:x, -3:y }
        // 0xA5 0x01 0x02 0x03 0x26 0x20 0x01 ...
        val coseKey = cborHeader(5, 5) +
                cborUint(1) + cborUint(2) +
                cborUint(3) + cborNegInt(7) +
                cborNegInt(1) + cborUint(1) +
                cborNegInt(2) + cborBytes(x) +
                cborNegInt(3) + cborBytes(y)

        val spki = CoseToSpkiConverter.convert(coseKey)
        assertNotNull(spki)
        
        // Expected SPKI for this key
        // We can assert the exact bytes or just structure checks.
        // For deterministic conformance, let's assert exact bytes.
        // This expected value is derived from standard SPKI structure for P-256.
        val expectedSpkiHex = "3059301306072A8648CE3D020106082A8648CE3D030107034200045A2C5974052026410260408542981326466352010813892795856407289569739871348419688404874312689252327591605332849202029304670058814521"
        assertEquals(expectedSpkiHex.lowercase(), bytesToHex(spki).lowercase())
    }

    @Test
    fun testRsaKeyConversion() {
        // Example RSA Key
        // 1 (kty) : 3 (RSA)
        // 3 (alg) : -257 (RS256)
        // -1 (n) : ...
        // -2 (e) : ...
        
        val n = hexToBytes("D524671408899806584218941094892408010451") // truncated for brevity but valid DER integer
        val e = hexToBytes("010001") // 65537
        
        val coseKey = cborHeader(5, 4) +
                cborUint(1) + cborUint(3) +
                cborUint(3) + cborNegInt(257) +
                cborNegInt(1) + cborBytes(n) +
                cborNegInt(2) + cborBytes(e)

        val spki = CoseToSpkiConverter.convert(coseKey)
        assertNotNull(spki)
        
        // Expected SPKI
        // SEQUENCE { SEQUENCE { OID(rsaEncryption), NULL }, BIT STRING (SEQUENCE { INTEGER(n), INTEGER(e) }) }
        // Let's verify start of SPKI which contains the OID
        val spkiHex = bytesToHex(spki)
        val rsaOid = "300D06092A864886F70D0101010500" // 1.2.840.113549.1.1.1 + NULL
        // The SPKI should contain this sequence
        // SPKI = SEQUENCE (30) + Length + Sequence(Algo) + BitString(Key)
        // For RSA, the key is also a DER sequence of n and e.
        
        // Expected SPKI
        val expectedSpkiHex = "3030300d06092a864886f70d0101010500031f00301c021500d5246714088998065842189410948924080104510203010001"
        assertEquals(expectedSpkiHex.lowercase(), bytesToHex(spki).lowercase())
    }
    
    // Helpers
    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        check(clean.length % 2 == 0)
        return ByteArray(clean.length / 2) { i ->
            val s = clean.substring(i * 2, i * 2 + 2)
            s.toInt(16).toByte()
        }
    }
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Reuse CBOR builders from ParserTest
    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        val prefix = majorType shl 5
        return when {
            length < 24 -> byteArrayOf((prefix or length).toByte())
            length < 256 -> byteArrayOf((prefix or 24).toByte(), length.toByte())
            else -> byteArrayOf(
                (prefix or 25).toByte(),
                (length shr 8).toByte(),
                (length and 0xFF).toByte(),
            )
        }
    }
    private fun cborUint(value: Int) = cborHeader(0, value)
    private fun cborNegInt(posValue: Int) = cborHeader(1, posValue - 1)
    private fun cborBytes(value: ByteArray) = cborHeader(2, value.size) + value
}
