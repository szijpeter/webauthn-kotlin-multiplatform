package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
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
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertTrue

class CompositeAttestationVerifierTest {

    @Test
    fun verifyDispatchesToNone() {
        // fmt="none", minimal attStmt
        val attestationObject = cborMap(
            "fmt" to cborText("none"),
            "attStmt" to cborMap(),
            "authData" to cborBytes(ByteArray(37)) // Mock authData
        )
        val verifier = CompositeAttestationVerifier()
        val input = sampleInput(attestationObject)
        val result = verifier.verify(input)

        // NoneVerifier usually passes if fmt is none and attStmt is empty.
        // But NoneVerifier logic in repo:
        // "Verify that attStmt is empty."
        // And checks nothing else specific to attestation.
        // So checking "Valid" assumes inputs are valid for NoneVerifier.
        assertTrue(result is ValidationResult.Valid, "Expected Valid for none fmt")
    }

    @Test
    fun verifyFailsForUnsupportedFormat() {
        val attestationObject = cborMap(
            "fmt" to cborText("galaxy-quest"),
            "attStmt" to cborMap(),
            "authData" to cborBytes(ByteArray(37))
        )
        val verifier = CompositeAttestationVerifier()
        val input = sampleInput(attestationObject)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("Unsupported attestation format"))
        assertTrue(error.message.contains("galaxy-quest"))
    }

    @Test
    fun verifyFailsForPackedWhenVerifierMissing() {
        val attestationObject = cborMap(
            "fmt" to cborText("packed"),
            "attStmt" to cborMap("alg" to cborInt(-7), "sig" to cborBytes(ByteArray(64))),
            "authData" to cborBytes(ByteArray(37))
        )
        // No signature verifier provided
        val verifier = CompositeAttestationVerifier(signatureVerifier = null)
        val input = sampleInput(attestationObject)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("Packed attestation not supported"))
    }
    
    @Test
    fun verifyDispatchesToPackedWhenVerifierPresent() {
         val attestationObject = cborMap(
            "fmt" to cborText("packed"),
            "attStmt" to cborMap("alg" to cborInt(-7), "sig" to cborBytes(ByteArray(64))),
            "authData" to cborBytes(ByteArray(37)) // minimal
        )
        // Mock SignatureVerifier that returns true. Credential key must be valid COSE so packed verifier reaches the mock.
        val sigVerifier = SignatureVerifier { _, _, _, _ -> true }
        val minimalCoseKey = minimalCoseEc2P256()
        val verifier = CompositeAttestationVerifier(signatureVerifier = sigVerifier)
        val input = sampleInput(attestationObject, minimalCoseKey)
        val result = verifier.verify(input)
        
        // PackedVerifier checks sig. If returns true, result is valid.
        assertTrue(result is ValidationResult.Valid, "Expected Valid for packed fmt with mock verifier")
    }

    // Helpers
    private fun minimalCoseEc2P256(): ByteArray {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()
        return TestCoseHelpers.coseBytesFromPublicKey(keyPair.public)
    }

    private fun cborMapInt(vararg entries: Pair<Long, ByteArray>): ByteArray {
        var res = cborHeader(5, entries.size)
        entries.forEach { (k, v) -> res = concat(res, cborInt(k), v) }
        return res
    }

    private fun sampleInput(attestationObject: ByteArray, cosePublicKey: ByteArray = ByteArray(0)): RegistrationValidationInput {
         val clientDataJson = ByteArray(0)
         val credentialId = CredentialId.fromBytes(ByteArray(16))
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
                attestedCredentialData = AttestedCredentialData(ByteArray(16), credentialId, cosePublicKey)
            ),
            clientData = CollectedClientData("webauthn.create", Challenge.fromBytes(ByteArray(16){1}), Origin.parseOrThrow("https://example.com")),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    // CBOR helpers
    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var res = cborHeader(5, entries.size)
        entries.forEach { (k,v) -> res = concat(res, cborText(k), v) }
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
    private fun concat(vararg chunks: ByteArray): ByteArray {
        val size = chunks.sumOf { it.size }
        val res = ByteArray(size)
        var pos = 0
        chunks.forEach { it.copyInto(res, destinationOffset = pos); pos += it.size }
        return res
    }
}
