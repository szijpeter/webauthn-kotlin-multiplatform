package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertTrue

class AppleAttestationStatementVerifierTest {

    @Test
    fun verifyPassesForValidApple() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val nonce = sha256(authData + clientDataHash)

        val attCert = generateAppleAttestationCert(kp, nonce)
        val coseKey = generateCoseKey(kp.public as ECPublicKey)

        val attestationObject = buildAppleAttestationObject(
            x5c = listOf(attCert)
        )

        val verifier = AppleAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData, coseKey)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Valid, "Expected Valid, got $result")
    }

    @Test
    fun verifyFailsForNonceMismatch() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        
        // Generate cert with random nonce
        val attCert = generateAppleAttestationCert(kp, ByteArray(32) { 0xBB.toByte() })
        val coseKey = generateCoseKey(kp.public as ECPublicKey)

        val attestationObject = buildAppleAttestationObject(
            x5c = listOf(attCert)
        )

        val verifier = AppleAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData, coseKey)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Certificate nonce mismatch") })
    }

    @Test
    fun verifyFailsForMissingX5c() {
        val authData = sampleAuthDataBytes()
        val clientDataJson = ByteArray(0)
        val attestationObject = buildAppleAttestationObject(
            x5c = emptyList()
        )
        val verifier = AppleAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData, ByteArray(0))
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("x5c is required"))
    }
    
    @Test
    fun verifyFailsForMissingExtension() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = ByteArray(0)
        // Generate cert WITHOUT Apple extension
        val attCert = generateStandardCert(kp)
        val coseKey = generateCoseKey(kp.public as ECPublicKey)

        val attestationObject = buildAppleAttestationObject(
            x5c = listOf(attCert)
        )

        val verifier = AppleAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData, coseKey)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Apple extension not found") })
    }

    @Test
    fun sharedCryptoServices_noRegressionInValidAndInvalidCases() {
        val verifier = AppleAttestationStatementVerifier(
            digestService = JvmDigestService(),
            certificateInspector = JvmCertificateInspector(),
            certificateChainValidator = JvmCertificateChainValidator(),
            cosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
        )
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val nonce = sha256(authData + clientDataHash)
        val attCert = generateAppleAttestationCert(kp, nonce)
        val coseKey = generateCoseKey(kp.public as ECPublicKey)
        val attestationObject = buildAppleAttestationObject(x5c = listOf(attCert))
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData, coseKey)
        assertTrue(verifier.verify(input) is ValidationResult.Valid)

        val attestationObjectEmptyX5c = buildAppleAttestationObject(x5c = emptyList())
        val invalidInput = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObjectEmptyX5c, authData, ByteArray(0))
        val invalidResult = verifier.verify(invalidInput)
        assertTrue(invalidResult is ValidationResult.Invalid)
        assertTrue((invalidResult as ValidationResult.Invalid).errors.any { it.message.contains("x5c is required") })
    }

    @Test
    fun verifyFailsForPublicKeyMismatch() {
        val kp = generateES256KeyPair()
        val kp2 = generateES256KeyPair() // Different key
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val nonce = sha256(authData + clientDataHash)

        val attCert = generateAppleAttestationCert(kp, nonce)
        // Credential public key from DIFFERENT key
        val coseKey = generateCoseKey(kp2.public as ECPublicKey)

        val attestationObject = buildAppleAttestationObject(
            x5c = listOf(attCert)
        )

        val verifier = AppleAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData, coseKey)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Public key mismatch") })
    }

    // ---- Helpers ----

    private fun buildAppleAttestationObject(authData: ByteArray = sampleAuthDataBytes(), x5c: List<ByteArray>): ByteArray {
        // Only fmt and attStmt with x5c are required/checked by my impl (plus authData if parsed)
        return cborMap(
            "fmt" to cborText("apple"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "x5c" to cborArray(x5c.map { cborBytes(it) })
            )
        )
    }

    private fun generateAppleAttestationCert(keyPair: java.security.KeyPair, nonce: ByteArray): ByteArray {
        val subjectPublicKeyInfo = keyPair.public.encoded
        // Apple extension: 1.2.840.113635.100.8.2
        val appleOid = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x63, 0x64, 0x08, 0x02)
        // Value: OCTET STRING containing nonce.
        val innerValue = derOctetString(nonce)
        val extValue = derOctetString(innerValue) // Wrapped in OCTET STRING for Extension.extnValue
        
        val extensions = derSequence(
            derSequence(
                derOid(appleOid),
                extValue
            )
        )
        // Explicit tag 3 [3] for extensions in TBS
        val tbsextensions = derExplicit(3, extensions)

        val tbsCert = derSequence(
            derExplicit(0, derInteger(byteArrayOf(2))), // v3
            derInteger(byteArrayOf(1)), 
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02))),
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))),
            derSequence(derUtcTime("260101000000Z"), derUtcTime("270101000000Z")),
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))),
            derRaw(subjectPublicKeyInfo),
            tbsextensions
        )
        
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(tbsCert)
        val signatureBytes = sig.sign()

        return derSequence(
            derRaw(tbsCert),
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02))),
            derBitString(signatureBytes),
        )
    }
    
    private fun generateStandardCert(keyPair: java.security.KeyPair): ByteArray {
         val subjectPublicKeyInfo = keyPair.public.encoded
         val tbsCert = derSequence(
            derExplicit(0, derInteger(byteArrayOf(2))), // v3
            derInteger(byteArrayOf(1)), 
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02))),
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))),
            derSequence(derUtcTime("260101000000Z"), derUtcTime("270101000000Z")),
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))),
            derRaw(subjectPublicKeyInfo)
        )
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(tbsCert)
        val signatureBytes = sig.sign()

        return derSequence(
            derRaw(tbsCert),
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02))),
            derBitString(signatureBytes),
        )
    }

    private fun generateCoseKey(pub: ECPublicKey): ByteArray {
        // ES256 P-256
        val x = pub.w.affineX.toByteArray().let { if(it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1,33) else if (it.size < 32) ByteArray(32 - it.size) + it else it }
        val y = pub.w.affineY.toByteArray().let { if(it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1,33) else if (it.size < 32) ByteArray(32 - it.size) + it else it }
        
        return cborMap(
            "1" to cborInt(2), // kty: EC
            "3" to cborInt(-7), // alg: ES256
            "-1" to cborInt(1), // crv: P-256
            "-2" to cborBytes(x), // x
            "-3" to cborBytes(y)  // y
        )
    }
    
    // Helpers (duplicate from other tests)
    private fun sampleAuthDataBytes(): ByteArray {
        val rpIdHash = ByteArray(32) { 0x10 }
        val flags = byteArrayOf(0x41)
        val signCount = byteArrayOf(0, 0, 0, 1)
        return rpIdHash + flags + signCount + ByteArray(16) { 0x22 }
    }
    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    private fun generateES256KeyPair(): java.security.KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }
    
    private fun sampleInput(
        credentialId: CredentialId,
        clientDataJson: ByteArray,
        attestationObject: ByteArray,
        authData: ByteArray,
        credentialPublicKey: ByteArray,
    ): RegistrationValidationInput {
        return RegistrationValidationInput(
            options = PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(id = RpId.parseOrThrow("example.com"), name = "Example"),
                user = PublicKeyCredentialUserEntity(id = UserHandle.fromBytes(ByteArray(16){0}), name = "alice", displayName = "Alice"),
                challenge = Challenge.fromBytes(ByteArray(16){1}),
                pubKeyCredParams = emptyList(),
            ),
            response = RegistrationResponse(
                credentialId = credentialId,
                clientDataJson = Base64UrlBytes.fromBytes(clientDataJson),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject),
                rawAuthenticatorData = AuthenticatorData(ByteArray(32), 0, 0),
                attestedCredentialData = AttestedCredentialData(ByteArray(16), credentialId, credentialPublicKey)
            ),
            clientData = CollectedClientData("webauthn.create", Challenge.fromBytes(ByteArray(16){1}), Origin.parseOrThrow("https://example.com")),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    // ASN.1 helpers
    private fun derSequence(vararg items: ByteArray) = derTag(0x30, concat(*items))
    private fun derSet(vararg items: ByteArray) = derTag(0x31, concat(*items))
    private fun derInteger(value: ByteArray) = derTag(0x02, value)
    private fun derOctetString(value: ByteArray) = derTag(0x04, value)
    private fun derBitString(value: ByteArray) = derTag(0x03, concat(byteArrayOf(0), value))
    private fun derOid(value: ByteArray) = derTag(0x06, value)
    private fun derUtf8String(value: String) = derTag(0x0C, value.encodeToByteArray())
    private fun derUtcTime(value: String) = derTag(0x17, value.encodeToByteArray())
    private fun derExplicit(tag: Int, content: ByteArray) = derTag(0xA0 or tag, content)
    private fun derRaw(content: ByteArray) = content
    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        val len = if (content.size < 128) {
             byteArrayOf(content.size.toByte())
        } else if (content.size < 256) {
             byteArrayOf(0x81.toByte(), content.size.toByte())
        } else {
             byteArrayOf(0x82.toByte(), (content.size shr 8).toByte(), content.size.toByte())
        }
        return concat(byteArrayOf(tag.toByte()), len, content)
    }
    private fun concat(vararg chunks: ByteArray): ByteArray {
        val size = chunks.sumOf { it.size }
        val res = ByteArray(size)
        var pos = 0
        chunks.forEach { it.copyInto(res, destinationOffset = pos); pos += it.size }
        return res
    }

    // CBOR helpers
    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var res = cborHeader(5, entries.size)
        entries.forEach { (k,v) -> res = concat(res, if (k.toLongOrNull() != null) cborInt(k.toLong()) else cborText(k), v) }
        return res
    }
    private fun cborArray(items: List<ByteArray>): ByteArray {
        var res = cborHeader(4, items.size)
        items.forEach { res = concat(res, it) }
        return res
    }
    private fun cborText(s: String) = concat(cborHeader(3, s.length), s.encodeToByteArray())
    private fun cborBytes(b: ByteArray) = concat(cborHeader(2, b.size), b)
    private fun cborInt(v: Long): ByteArray {
        return if (v >= 0) cborHeader(0, v.toInt()) else {
             val encoded = -1L - v
             cborHeader(1, encoded.toInt())
        }
    }
    private fun cborHeader(major: Int, len: Int): ByteArray {
         val prefix = major shl 5
         return when {
             len < 24 -> byteArrayOf((prefix or len).toByte())
             len < 256 -> byteArrayOf((prefix or 24).toByte(), len.toByte())
             len < 65536 -> byteArrayOf((prefix or 25).toByte(), (len shr 8).toByte(), len.toByte())
             else -> {
                 val l = len.toLong()
                 byteArrayOf((prefix or 26).toByte(), (l shr 24).toByte(), (l shr 16).toByte(), (l shr 8).toByte(), l.toByte())
             }
         }
    }
}
