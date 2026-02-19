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
import java.security.interfaces.RSAPrivateKey
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertTrue

class AndroidSafetyNetAttestationStatementVerifierTest {

    @Test
    fun verifyPassesForValidSafetyNet() {
        // ... existing test body ...
        val kp = generateRSA2048KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val nonce = sha256(authData + clientDataHash)

        val certBytes = generateSelfSignedCert(kp)
        val certB64 = Base64.getEncoder().encodeToString(certBytes)
        
        val headerJson = """{"alg":"RS256","x5c":["$certB64"]}"""
        val payloadJson = """{"nonce":"${Base64.getEncoder().encodeToString(nonce)}","ctsProfileMatch":true,"timestampMs":1234567890}"""
        
        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray())
        
        val signedData = "$headerB64.$payloadB64".toByteArray()
        val sig = signRS256(kp.private as RSAPrivateKey, signedData)
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
        
        val jws = "$headerB64.$payloadB64.$sigB64"

        val attestationObject = buildSafetyNetAttestationObject(jws, authData)

        val verifier = AndroidSafetyNetAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Valid, "Expected Valid, got $result")
    }

    @Test
    fun verifyPassesWithTrustAnchorValidation() {
        val kp = generateRSA2048KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val nonce = sha256(authData + clientDataHash)

        val certBytes = generateSelfSignedCert(kp)
        val certB64 = Base64.getEncoder().encodeToString(certBytes)
        
        // Use the cert itself as the trust anchor
        val trustSource = dev.webauthn.crypto.TrustAnchorSource { _ -> listOf(certBytes) }
        val chainVerifier = TrustChainVerifier(trustSource)

        val headerJson = """{"alg":"RS256","x5c":["$certB64"]}"""
        val payloadJson = """{"nonce":"${Base64.getEncoder().encodeToString(nonce)}","ctsProfileMatch":true,"timestampMs":1234567890}"""
        
        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray())
        
        val signedData = "$headerB64.$payloadB64".toByteArray()
        val sig = signRS256(kp.private as RSAPrivateKey, signedData)
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
        
        val jws = "$headerB64.$payloadB64.$sigB64"

        val attestationObject = buildSafetyNetAttestationObject(jws, authData)

        val verifier = AndroidSafetyNetAttestationStatementVerifier(trustChainVerifier = chainVerifier)
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Valid, "Expected Valid with trust anchor, got $result")
    }


    @Test
    fun sharedCryptoServices_noRegressionInValidAndInvalidCases() {
        val verifier = AndroidSafetyNetAttestationStatementVerifier(
            certificateInspector = JvmCertificateInspector(),
        )
        val kp = generateRSA2048KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val nonce = sha256(authData + clientDataHash)
        val certBytes = generateSelfSignedCert(kp)
        val certB64 = Base64.getEncoder().encodeToString(certBytes)
        val headerJson = """{"alg":"RS256","x5c":["$certB64"]}"""
        val payloadJson = """{"nonce":"${Base64.getEncoder().encodeToString(nonce)}","ctsProfileMatch":true,"timestampMs":1234567890}"""
        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray())
        val signedData = "$headerB64.$payloadB64".toByteArray()
        val sig = signRS256(kp.private as RSAPrivateKey, signedData)
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
        val jws = "$headerB64.$payloadB64.$sigB64"
        val attestationObject = buildSafetyNetAttestationObject(jws, authData)
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        assertTrue(verifier.verify(input) is ValidationResult.Valid)

        val wrongNonce = sha256("wrong".toByteArray())
        val payloadWrong = """{"nonce":"${Base64.getEncoder().encodeToString(wrongNonce)}","ctsProfileMatch":true}"""
        val payloadB64Wrong = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadWrong.toByteArray())
        val signedDataWrong = "$headerB64.$payloadB64Wrong".toByteArray()
        val sigWrong = signRS256(kp.private as RSAPrivateKey, signedDataWrong)
        val jwsWrong = "$headerB64.$payloadB64Wrong.${Base64.getUrlEncoder().withoutPadding().encodeToString(sigWrong)}"
        val invalidAttestation = buildSafetyNetAttestationObject(jwsWrong, authData)
        val invalidInput = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, invalidAttestation, authData)
        val invalidResult = verifier.verify(invalidInput)
        assertTrue(invalidResult is ValidationResult.Invalid)
        assertTrue((invalidResult as ValidationResult.Invalid).errors.any { it.message.contains("Nonce mismatch") })
    }

    @Test
    fun verifyFailsForInvalidNonce() {
        val kp = generateRSA2048KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        
        val certBytes = generateSelfSignedCert(kp)
        val certB64 = Base64.getEncoder().encodeToString(certBytes)
        
        val headerJson = """{"alg":"RS256","x5c":["$certB64"]}"""
        // Invalid nonce (Base64 of random bytes)
        val invalidNonce = Base64.getEncoder().encodeToString(ByteArray(32))
        val payloadJson = """{"nonce":"$invalidNonce","ctsProfileMatch":true}"""
        
        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray())
        
        val signedData = "$headerB64.$payloadB64".toByteArray()
        val sig = signRS256(kp.private as RSAPrivateKey, signedData)
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
        
        val jws = "$headerB64.$payloadB64.$sigB64"

        val attestationObject = buildSafetyNetAttestationObject(jws, authData)

        val verifier = AndroidSafetyNetAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Nonce mismatch") })
    }

    private fun buildSafetyNetAttestationObject(jws: String, authData: ByteArray): ByteArray {
        return cborMap(
            "fmt" to cborText("android-safetynet"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "ver" to cborText("123"), // version string
                "response" to cborBytes(jws.toByteArray())
            )
        )
    }

    // Helpers
    private fun sampleAuthDataBytes(): ByteArray {
        val rpIdHash = ByteArray(32) { 0x10 }
        val flags = byteArrayOf(0x41)
        val signCount = byteArrayOf(0, 0, 0, 1)
        return rpIdHash + flags + signCount + ByteArray(16) { 0x22 }
    }
    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    
    private fun generateRSA2048KeyPair(): java.security.KeyPair {
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(2048)
        return gen.generateKeyPair()
    }
    
    private fun signRS256(privateKey: RSAPrivateKey, data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }
    
    private fun generateSelfSignedCert(keyPair: java.security.KeyPair): ByteArray {
        // Minimal valid self-signed RSA cert
        val subjectPublicKeyInfo = keyPair.public.encoded
        val tbsCert = derSequence(
            derExplicit(0, derInteger(byteArrayOf(2))), // v3
            derInteger(byteArrayOf(1)), 
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B))), // sha256WithRSAEncryption
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))),
            derSequence(derUtcTime("260101000000Z"), derUtcTime("270101000000Z")),
            derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)), derUtf8String("Test")))),
            derRaw(subjectPublicKeyInfo)
        )
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(keyPair.private)
        sig.update(tbsCert)
        val signatureBytes = sig.sign()

        return derSequence(
            derRaw(tbsCert),
            derSequence(derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B))),
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
