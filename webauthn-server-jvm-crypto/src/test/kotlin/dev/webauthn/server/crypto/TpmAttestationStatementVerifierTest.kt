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
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertTrue

class TpmAttestationStatementVerifierTest {

    @Test
    fun verifyPassesForValidTpm() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)

        val certInfo = createCertInfo(
            magic = 0xFF544347.toInt(),
            type = 0x8017.toShort(),
            extraData = concatHash,
            signerName = ByteArray(10) { 0xFF.toByte() } // arbitrary signer name
        )
        
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, certInfo)

        val attCert = generateAttestationCert(kp) // minimal valid x509

        val attestationObject = buildTpmAttestationObject(
            ver = "2.0",
            alg = -7,
            sig = sig,
            certInfo = certInfo,
            pubArea = ByteArray(10), // arbitrary
            x5c = listOf(attCert)
        )

        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Valid, "Expected Valid, got $result")
    }

    @Test
    fun verifyFailsForWrongVersion() {
        val authData = sampleAuthDataBytes()
        val clientDataJson = ByteArray(0)
        val attestationObject = buildTpmAttestationObject(
            ver = "1.0", // Wrong version
            alg = -7,
            sig = ByteArray(64),
            certInfo = ByteArray(10),
            pubArea = ByteArray(10),
            x5c = listOf(ByteArray(0))
        )
        // Should parse but fail version check
        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("TPM version must be 2.0"))
    }

    @Test
    fun verifyFailsForBadMagic() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)

        // Wrong magic
        val certInfo = createCertInfo(
            magic = 0xDEADBEEF.toInt(), 
            type = 0x8017.toShort(),
            extraData = concatHash,
            signerName = ByteArray(10)
        )
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, certInfo)
        val attCert = generateAttestationCert(kp)

        val attestationObject = buildTpmAttestationObject(
            ver = "2.0",
            alg = -7,
            sig = sig,
            certInfo = certInfo,
            pubArea = ByteArray(10),
            x5c = listOf(attCert)
        )
        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Invalid magic") })
    }

    @Test
    fun verifyFailsForSignatureMismatch() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)

        val certInfo = createCertInfo(
            magic = 0xFF544347.toInt(),
            type = 0x8017.toShort(),
            extraData = concatHash, // Correct hash
            signerName = ByteArray(10)
        )
        // Sign WRONG data
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, ByteArray(10)) 
        
        val attCert = generateAttestationCert(kp)

        val attestationObject = buildTpmAttestationObject(
            ver = "2.0",
            alg = -7,
            sig = sig,
            certInfo = certInfo,
            pubArea = ByteArray(10),
            x5c = listOf(attCert)
        )
        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Invalid signature") })
    }


    // ---- Helpers ----

    private fun createCertInfo(magic: Int, type: Short, extraData: ByteArray, signerName: ByteArray): ByteArray {
        // Estimate size: 4 + 2 + (2+signer) + (2+extra) + 17 + 8 + ...
        val signerLen = signerName.size
        val extraLen = extraData.size
        // clockInfo (17), firmware (8), attested (variable).
        // attested for certify: name (2+nameLen) + qualifiedName (2+qNameLen).
        // Minimal mockup: use just enough to parse extraData.
        val size = 4 + 2 + 2 + signerLen + 2 + extraLen + 100 // buffer
        val buf = ByteBuffer.allocate(size)
        buf.putInt(magic)
        buf.putShort(type)
        buf.putShort(signerLen.toShort())
        buf.put(signerName)
        buf.putShort(extraLen.toShort())
        buf.put(extraData)
        // Add minimal dummy data for rest to allow parsing if we parsed more?
        // Parser only reads up to extraData. So this is enough.
        return buf.array().copyOf(buf.position())
    }

    private fun sampleAuthDataBytes(): ByteArray {
        val rpIdHash = ByteArray(32) { 0x10 }
        val flags = byteArrayOf(0x41)
        val signCount = byteArrayOf(0, 0, 0, 1)
        return rpIdHash + flags + signCount + ByteArray(16) { 0x22 }
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun generateES256KeyPair(): java.security.KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }

    private fun signES256(privateKey: java.security.interfaces.ECPrivateKey, data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    @Test
    fun verifyFailsForAikCertWithCaTrue() {
        // ... (setup similar to valid case) ...
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)

        val certInfo = createCertInfo(
            magic = 0xFF544347.toInt(),
            type = 0x8017.toShort(),
            extraData = concatHash,
            signerName = ByteArray(10)
        )
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, certInfo)
        
        // Generate INVALID cert: CA=true
        val attCert = generateAttestationCert(kp, isCa = true)

        val attestationObject = buildTpmAttestationObject(
            ver = "2.0",
            alg = -7,
            sig = sig,
            certInfo = certInfo,
            pubArea = ByteArray(10),
            x5c = listOf(attCert)
        )
        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("AIK certificate must not be a CA") })
    }

    @Test
    fun verifyFailsForAikCertMissingEku() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)

        val certInfo = createCertInfo(
            magic = 0xFF544347.toInt(),
            type = 0x8017.toShort(),
            extraData = concatHash,
            signerName = ByteArray(10)
        )
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, certInfo)

        // Generate INVALID cert: Missing EKU
        val attCert = generateAttestationCert(kp, includeEku = false)

        val attestationObject = buildTpmAttestationObject(
            ver = "2.0",
            alg = -7,
            sig = sig,
            certInfo = certInfo,
            pubArea = ByteArray(10),
            x5c = listOf(attCert) // Invalid cert
        )
        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("AIK certificate missing tcg-kp-AIKCertificate EKU") })
    }

    @Test
    fun verifyFailsForAikCertWithCriticalSan() {
         val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)

        val certInfo = createCertInfo(
            magic = 0xFF544347.toInt(),
            type = 0x8017.toShort(),
            extraData = concatHash,
            signerName = ByteArray(10)
        )
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, certInfo)

        // Generate INVALID cert: Critical SAN
        val attCert = generateAttestationCert(kp, criticalSan = true)

        val attestationObject = buildTpmAttestationObject(
            ver = "2.0",
            alg = -7,
            sig = sig,
            certInfo = certInfo,
            pubArea = ByteArray(10),
            x5c = listOf(attCert) // Invalid cert
        )
        val verifier = TpmAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("AIK certificate SAN extension must not be critical") })
    }

    private fun generateAttestationCert(
        keyPair: java.security.KeyPair,
        isCa: Boolean = false,
        includeEku: Boolean = true,
        criticalSan: Boolean = false
    ): ByteArray {
        val subjectPublicKeyInfo = keyPair.public.encoded
        
        // Extension Construction
        val extensionsList = mutableListOf<ByteArray>()

        // 1. BasicConstraints (OID 2.5.29.19)
        val bcValue = if (isCa) {
             derSequence(derBoolean(true))
        } else {
             derSequence() // cA default false
        }
        extensionsList.add(derExtension(
            byteArrayOf(0x55, 0x1D, 0x13), // 2.5.29.19
            true,
            derOctetString(bcValue)
        ))

        // 2. ExtendedKeyUsage (OID 2.5.29.37)
        if (includeEku) {
            // tcg-kp-AIKCertificate (2.23.133.8.3)
            // OID bytes: 2.23.133.8.3 -> 0x67 0x81 0x05 0x08 0x03
            val aikOid = byteArrayOf(0x67, 0x81.toByte(), 0x05, 0x08, 0x03)
            val ekuValue = derSequence(derOid(aikOid))
            extensionsList.add(derExtension(
                byteArrayOf(0x55, 0x1D, 0x25), // 2.5.29.37
                false, // Critical MUST be false
                derOctetString(ekuValue)
            ))
        }

        // 3. SubjectAlternativeName (OID 2.5.29.17) - Optional
        if (criticalSan) {
             // Add dummy SAN
             val sanValue = derSequence(derTag(0x82, "test".toByteArray())) // dNSName context specific 2
             extensionsList.add(derExtension(
                 byteArrayOf(0x55, 0x1D, 0x11), // 2.5.29.17
                 true, // Invalid if critical
                 derOctetString(sanValue)
             ))
        }

        val extensions = derExplicit(3, derSequence(*extensionsList.toTypedArray()))

        val tbsCert = derSequence(
            derExplicit(0, derInteger(byteArrayOf(2))), // v3
            derInteger(byteArrayOf(1)), // Serial
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02))), // ecdsa-with-sha256
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))), // Issuer
            derSequence(derUtcTime("260101000000Z"), derUtcTime("270101000000Z")),
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))), // Subject
            derRaw(subjectPublicKeyInfo),
            extensions // Add extensions here
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

    private fun sampleInput(
        credentialId: CredentialId,
        clientDataJson: ByteArray,
        attestationObject: ByteArray,
        authData: ByteArray,
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
                attestedCredentialData = AttestedCredentialData(ByteArray(16), credentialId, ByteArray(0))
            ),
            clientData = CollectedClientData("webauthn.create", Challenge.fromBytes(ByteArray(16){1}), Origin.parseOrThrow("https://example.com")),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    private fun buildTpmAttestationObject(authData: ByteArray = sampleAuthDataBytes(), ver: String, alg: Long, sig: ByteArray, certInfo: ByteArray, pubArea: ByteArray, x5c: List<ByteArray>): ByteArray {
        return cborMap(
            "fmt" to cborText("tpm"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "ver" to cborText(ver),
                "alg" to cborInt(alg),
                "sig" to cborBytes(sig),
                "certInfo" to cborBytes(certInfo),
                "pubArea" to cborBytes(pubArea),
                "x5c" to cborArray(x5c.map { cborBytes(it) })
            )
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
    // Correct implementation based on usage:
    // derExtension(oid, critical, octetStringWrappedValue)
    private fun derExtension(oid: ByteArray, critical: Boolean, value: ByteArray): ByteArray {
        return if (critical) {
            derSequence(derOid(oid), derBoolean(true), value)
        } else {
            derSequence(derOid(oid), value)
        }
    }

    private fun derBoolean(value: Boolean): ByteArray = derTag(0x01, byteArrayOf(if (value) 0xFF.toByte() else 0x00))
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
        entries.forEach { (k,v) -> res = concat(res, cborText(k), v) }
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

    @Test
    fun sharedCryptoServices_noRegressionInValidAndInvalidCases() {
        val verifier = TpmAttestationStatementVerifier(
            certificateInspector = JvmCertificateInspector(),
        )
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val concatHash = sha256(authData + clientDataHash)
        val certInfo = createCertInfo(magic = 0xFF544347.toInt(), type = 0x8017.toShort(), extraData = concatHash, signerName = ByteArray(10) { 0xFF.toByte() })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, certInfo)
        val attCert = generateAttestationCert(kp)
        val attestationObject = buildTpmAttestationObject(ver = "2.0", alg = -7L, sig = sig, certInfo = certInfo, pubArea = ByteArray(10), x5c = listOf(attCert))
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        assertTrue(verifier.verify(input) is ValidationResult.Valid)

        val wrongVerObject = buildTpmAttestationObject(ver = "1.0", alg = -7L, sig = ByteArray(64), certInfo = ByteArray(10), pubArea = ByteArray(10), x5c = listOf(ByteArray(0)))
        val invalidInput = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, wrongVerObject, authData)
        val invalidResult = verifier.verify(invalidInput)
        assertTrue(invalidResult is ValidationResult.Invalid)
        assertTrue((invalidResult as ValidationResult.Invalid).errors.any { it.message.contains("TPM version must be 2.0") })
    }
}
