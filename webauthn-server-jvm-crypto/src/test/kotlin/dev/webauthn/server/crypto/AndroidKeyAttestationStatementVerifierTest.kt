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
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertTrue

class AndroidKeyAttestationStatementVerifierTest {

    @Test
    fun verifyPassesForValidAndroidKeyAttestation() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        // Construct extension value: SEQUENCE pointing to challenge = clientDataHash
        // KeyDescription schema:
        // Version(Int), SecLevel(Int), KMVer(Int), KMSecLevel(Int), Challenge(OctetString), ...
        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), // Version
            derInteger(byteArrayOf(0)), // SecurityLevel
            derInteger(byteArrayOf(0)), // KeymasterVersion
            derInteger(byteArrayOf(0)), // KeymasterSecurityLevel
            derOctetString(clientDataHash), // Challenge
            derOctetString(ByteArray(0)), // UniqueId
            derSequence(), // swEnforced
            derSequence()  // teeEnforced
        )
        // The extension value itself must be an OCTET STRING containing the DER of the sequence
        val extensionValue = derOctetString(extensionValueSeq)

        val attCert = generateAttestationCert(kp, extensionValue)

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        val attestationObject = buildAndroidKeyAttestationObject(
            authData = authData,
            alg = -7, // ES256
            sig = sig,
            x5c = listOf(attCert),
        )

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)

        val result = verifier.verify(input)
        println("Debug result: $result")
        assertTrue(result is ValidationResult.Valid, "Expected Valid, got $result")
    }

    @Test
    fun verifyFailsForChallengeMismatch() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        
        // Use WRONG challenge in certificate
        val wrongHash = ByteArray(32) { 0xFF.toByte() }
        
        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derOctetString(wrongHash), // Mismatch!
            derOctetString(ByteArray(0)),
            derSequence(),
            derSequence()
        )
        val extensionValue = derOctetString(extensionValueSeq)

        val attCert = generateAttestationCert(kp, extensionValue)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataHash = sha256(clientDataJson)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        val attestationObject = buildAndroidKeyAttestationObject(
            authData = authData,
            alg = -7,
            sig = sig,
            x5c = listOf(attCert),
        )

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)

        val result = verifier.verify(input)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun verifyFailsWhenAllApplicationsPresent() {
        // [600] EXPLICIT NULL
        // Tag 600 = 0xBF8458
        // NULL = 05 00
        val allApplications = derTag(0xBF8458, byteArrayOf(0x05, 0x00))

        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash),
            derOctetString(ByteArray(0)),
            derSequence(), // swEnforced
            derSequence(allApplications) // teeEnforced with allApplications (should fail)
        )
        val extensionValue = derOctetString(extensionValueSeq)
        val attCert = generateAttestationCert(kp, extensionValue)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase) 
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("allApplications"))
    }

    @Test
    fun verifyFailsWhenOriginNotGenerated() {
        // [702] EXPLICIT INTEGER (1) - 1 means KM_ORIGIN_IMPORTED (or similar, != GENERATED)
        // Tag 702 = 0xBF853E
        val originImported = derTag(0xBF853E, derInteger(byteArrayOf(1)))

        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash),
            derOctetString(ByteArray(0)),
            derSequence(), // swEnforced
            derSequence(originImported) // teeEnforced with bad origin
        )
        val extensionValue = derOctetString(extensionValueSeq)
        val attCert = generateAttestationCert(kp, extensionValue)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("Key origin is not GENERATED"))
    }


    // ---- Helpers ----

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

    private fun generateAttestationCert(keyPair: java.security.KeyPair, extensionValueEncoded: ByteArray?, extensionOid: ByteArray = byteArrayOf(0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6.toByte(), 0x79, 0x02, 0x01, 0x11)): ByteArray {
        val subjectPublicKeyInfo = keyPair.public.encoded
        val rdn = derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test Authenticator"))))
        
        val extensions = if (extensionValueEncoded != null) {
             derTag(0xA3, derSequence(
                derSequence(
                    derOid(extensionOid),
                    extensionValueEncoded
                )
            ))
        } else byteArrayOf()

        val tbsCertContent = mutableListOf(
            derExplicit(0, derInteger(byteArrayOf(0x02))), // v3
            derInteger(byteArrayOf(0x01)), // Serial
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02))),
            rdn,
            derSequence(derUtcTime("260101000000Z"), derUtcTime("270101000000Z")),
            rdn,
            derRaw(subjectPublicKeyInfo)
        )
        if (extensions.isNotEmpty()) {
            tbsCertContent.add(extensions)
        }

        val tbsCert = derSequence(*tbsCertContent.toTypedArray())

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
                attestedCredentialData = AttestedCredentialData(credentialId, ByteArray(0))
            ),
            clientData = CollectedClientData("webauthn.create", Challenge.fromBytes(ByteArray(16){1}), Origin.parseOrThrow("https://example.com")),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    private fun buildAndroidKeyAttestationObject(authData: ByteArray, alg: Long, sig: ByteArray, x5c: List<ByteArray>): ByteArray {
        return cborMap(
            "fmt" to cborText("android-key"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "alg" to cborInt(alg),
                "sig" to cborBytes(sig),
                "x5c" to cborArray(x5c.map { cborBytes(it) })
            )
        )
    }

    // ASN.1 helpers (mini copy for self-contained test)
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
        val tagBytes = if (tag == 0xBF8458) byteArrayOf(0xBF.toByte(), 0x84.toByte(), 0x58.toByte())
        else if (tag == 0xBF853E) byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x3E.toByte())
        else if (tag > 255) throw IllegalArgumentException("Unsupported tag: $tag")
        else byteArrayOf(tag.toByte())
        
        val len = if (content.size < 128) {
            byteArrayOf(content.size.toByte())
        } else if (content.size < 256) {
            byteArrayOf(0x81.toByte(), content.size.toByte())
        } else {
            byteArrayOf(0x82.toByte(), (content.size shr 8).toByte(), content.size.toByte())
        }
        return concat(tagBytes, len, content)
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
}
