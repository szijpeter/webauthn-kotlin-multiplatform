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
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertTrue

class FidoU2fAttestationStatementVerifierTest {

    @Test
    fun verifyPassesForValidU2fAttestation() {
        val credentialKeyPair = generateCredentialKeyPair()
        val credentialPublicKey = credentialKeyPair.public as ECPublicKey
        val x = credentialPublicKey.w.affineX.toByteArray().ensure32()
        val y = credentialPublicKey.w.affineY.toByteArray().ensure32()

        val coseKey = cborMap(
            1 to cborInt(2),
            3 to cborInt(-7),
            -1 to cborInt(1),
            -2 to cborBytes(x),
            -3 to cborBytes(y),
        )

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x33 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AQID","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val rpIdHash = sha256("example.com".toByteArray())

        val publicKeyU2F = byteArrayOf(0x04) + x + y
        val verificationData = byteArrayOf(0x00) + rpIdHash + clientDataHash + credentialId.value.bytes() + publicKeyU2F

        val attestationPrivateKey = loadAttestationPrivateKey()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(attestationPrivateKey)
        signature.update(verificationData)
        val sig = signature.sign()

        val authData = rpIdHash +
            byteArrayOf(0x41) +
            byteArrayOf(0, 0, 0, 1) +
            ByteArray(16) +
            byteArrayOf(0, 16) +
            credentialId.value.bytes() +
            coseKey

        val attestationObject = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "sig" to cborBytes(sig),
                "x5c" to cborArray(listOf(cborBytes(loadAttestationCertificate()))),
            ),
        )

        val verifier = FidoU2fAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, coseKey, rpIdHash)

        val result = verifier.verify(input)
        assertTrue(result is ValidationResult.Valid, "Expected Valid but got: $result")
    }

    @Test
    fun verifyFailsWhenX5cMissing() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val clientDataJson = "{}".toByteArray()
        val rpIdHash = sha256("example.com".toByteArray())
        val coseKey = cborMap(1 to cborInt(2), -2 to cborBytes(ByteArray(32) { 1 }), -3 to cborBytes(ByteArray(32) { 2 }))

        val attestationObject = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(ByteArray(37)),
            "attStmt" to cborMap("sig" to cborBytes(byteArrayOf(1, 2, 3))),
        )

        val result = FidoU2fAttestationStatementVerifier().verify(
            sampleInput(credentialId, clientDataJson, attestationObject, coseKey, rpIdHash),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun verifyFailsWhenSigMissing() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x22 })
        val clientDataJson = "{}".toByteArray()
        val rpIdHash = sha256("example.com".toByteArray())
        val coseKey = cborMap(1 to cborInt(2), -2 to cborBytes(ByteArray(32) { 1 }), -3 to cborBytes(ByteArray(32) { 2 }))

        val attestationObject = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(ByteArray(37)),
            "attStmt" to cborMap("x5c" to cborArray(listOf(cborBytes(loadAttestationCertificate())))),
        )

        val result = FidoU2fAttestationStatementVerifier().verify(
            sampleInput(credentialId, clientDataJson, attestationObject, coseKey, rpIdHash),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun verifyFailsForInvalidSignature() {
        val credentialKeyPair = generateCredentialKeyPair()
        val credentialPublicKey = credentialKeyPair.public as ECPublicKey
        val x = credentialPublicKey.w.affineX.toByteArray().ensure32()
        val y = credentialPublicKey.w.affineY.toByteArray().ensure32()
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x44 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AQID","origin":"https://example.com"}""".toByteArray()
        val rpIdHash = sha256("example.com".toByteArray())

        val coseKey = cborMap(
            1 to cborInt(2),
            3 to cborInt(-7),
            -1 to cborInt(1),
            -2 to cborBytes(x),
            -3 to cborBytes(y),
        )

        val attestationPrivateKey = loadAttestationPrivateKey()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(attestationPrivateKey)
        signature.update(byteArrayOf(9, 9, 9)) // sign wrong payload so verification must fail
        val wrongSig = signature.sign()

        val authData = rpIdHash +
            byteArrayOf(0x41) +
            byteArrayOf(0, 0, 0, 1) +
            ByteArray(16) +
            byteArrayOf(0, 16) +
            credentialId.value.bytes() +
            coseKey

        val attestationObject = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "sig" to cborBytes(wrongSig),
                "x5c" to cborArray(listOf(cborBytes(loadAttestationCertificate()))),
            ),
        )

        val result = FidoU2fAttestationStatementVerifier().verify(
            sampleInput(credentialId, clientDataJson, attestationObject, coseKey, rpIdHash),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun verifyFailsForMalformedCosePublicKey() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x55 })
        val clientDataJson = "{}".toByteArray()
        val rpIdHash = sha256("example.com".toByteArray())
        val malformedCose = cborMap(
            1 to cborInt(2),
            -2 to cborBytes(ByteArray(32) { 1 }),
        )

        val attestationObject = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(ByteArray(37)),
            "attStmt" to cborMap(
                "sig" to cborBytes(byteArrayOf(1, 2, 3, 4)),
                "x5c" to cborArray(listOf(cborBytes(loadAttestationCertificate()))),
            ),
        )

        val result = FidoU2fAttestationStatementVerifier().verify(
            sampleInput(credentialId, clientDataJson, attestationObject, malformedCose, rpIdHash),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    private fun sampleInput(
        credentialId: CredentialId,
        clientDataJson: ByteArray,
        attestationObject: ByteArray,
        cosePublicKey: ByteArray,
        rpIdHash: ByteArray,
    ): RegistrationValidationInput {
        return RegistrationValidationInput(
            options = PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
                user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(ByteArray(16)), "alice", "Alice"),
                challenge = Challenge.fromBytes(ByteArray(16) { 1 }),
                pubKeyCredParams = emptyList(),
            ),
            response = RegistrationResponse(
                credentialId = credentialId,
                clientDataJson = Base64UrlBytes.fromBytes(clientDataJson),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject),
                rawAuthenticatorData = AuthenticatorData(rpIdHash, 0x41, 1),
                attestedCredentialData = AttestedCredentialData(ByteArray(16), credentialId, cosePublicKey),
            ),
            clientData = CollectedClientData(
                "webauthn.create",
                Challenge.fromBytes(ByteArray(16) { 1 }),
                Origin.parseOrThrow("https://example.com"),
            ),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    @Test
    fun sharedCryptoServices_noRegressionInValidAndInvalidCases() {
        val verifier = FidoU2fAttestationStatementVerifier()
        val credentialKeyPair = generateCredentialKeyPair()
        val credentialPublicKey = credentialKeyPair.public as ECPublicKey
        val x = credentialPublicKey.w.affineX.toByteArray().ensure32()
        val y = credentialPublicKey.w.affineY.toByteArray().ensure32()
        val coseKey = cborMap(
            1 to cborInt(2), 3 to cborInt(-7), -1 to cborInt(1),
            -2 to cborBytes(x), -3 to cborBytes(y),
        )
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x33 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AQID","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val rpIdHash = sha256("example.com".toByteArray())
        val publicKeyU2F = byteArrayOf(0x04) + x + y
        val verificationData = byteArrayOf(0x00) + rpIdHash + clientDataHash + credentialId.value.bytes() + publicKeyU2F
        val attestationPrivateKey = loadAttestationPrivateKey()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(attestationPrivateKey)
        signature.update(verificationData)
        val sig = signature.sign()
        val authData = rpIdHash + byteArrayOf(0x41) + byteArrayOf(0, 0, 0, 1) + ByteArray(16) + byteArrayOf(0, 16) + credentialId.value.bytes() + coseKey
        val attestationObject = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "sig" to cborBytes(sig),
                "x5c" to cborArray(listOf(cborBytes(loadAttestationCertificate()))),
            ),
        )
        val input = sampleInput(credentialId, clientDataJson, attestationObject, coseKey, rpIdHash)
        assertTrue(verifier.verify(input) is ValidationResult.Valid)

        val attestationObjectMissingX5c = cborMap(
            "fmt" to cborText("fido-u2f"),
            "authData" to cborBytes(ByteArray(37)),
            "attStmt" to cborMap("sig" to cborBytes(byteArrayOf(1, 2, 3))),
        )
        val invalidResult = verifier.verify(sampleInput(credentialId, clientDataJson, attestationObjectMissingX5c, coseKey, rpIdHash))
        assertTrue(invalidResult is ValidationResult.Invalid)
    }

    private fun loadAttestationPrivateKey(): PrivateKey {
        val der = loadFixtureBytes("attestation-key-pkcs8.der.b64")
        val keySpec = PKCS8EncodedKeySpec(der)
        return KeyFactory.getInstance("EC").generatePrivate(keySpec)
    }

    private fun loadAttestationCertificate(): ByteArray {
        return loadFixtureBytes("attestation-cert.der.b64")
    }

    private fun loadFixtureBytes(name: String): ByteArray {
        val resource = checkNotNull(javaClass.getResource("/fido-u2f/$name")) {
            "Missing fixture resource: $name"
        }
        val content = resource.readText().trim()
        return Base64.getDecoder().decode(content)
    }

    private fun generateCredentialKeyPair(): java.security.KeyPair {
        val random = SecureRandom.getInstance("SHA1PRNG")
        random.setSeed(byteArrayOf(0x01, 0x23, 0x45, 0x67))
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"), random)
        return gen.generateKeyPair()
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun ByteArray.ensure32(): ByteArray {
        return if (size == 32) {
            this
        } else if (size > 32) {
            copyOfRange(size - 32, size)
        } else {
            ByteArray(32 - size) + this
        }
    }

    private fun cborMap(vararg entries: Pair<Any, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        for ((key, value) in entries) {
            result += when (key) {
                is String -> cborText(key)
                is Int -> cborInt(key.toLong())
                is Long -> cborInt(key)
                else -> error("Unsupported CBOR map key type")
            }
            result += value
        }
        return result
    }

    private fun cborArray(items: List<ByteArray>): ByteArray {
        var result = cborHeader(4, items.size)
        for (item in items) {
            result += item
        }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return cborHeader(3, bytes.size) + bytes
    }

    private fun cborBytes(value: ByteArray): ByteArray = cborHeader(2, value.size) + value

    private fun cborInt(value: Long): ByteArray {
        return if (value >= 0) {
            cborHeader(0, value.toInt())
        } else {
            cborHeader(1, (-1L - value).toInt())
        }
    }

    private fun cborHeader(major: Int, length: Int): ByteArray {
        return when {
            length < 24 -> byteArrayOf((major shl 5 or length).toByte())
            length < 256 -> byteArrayOf((major shl 5 or 24).toByte(), length.toByte())
            length < 65536 -> byteArrayOf(
                (major shl 5 or 25).toByte(),
                ((length shr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte(),
            )
            else -> byteArrayOf(
                (major shl 5 or 26).toByte(),
                ((length shr 24) and 0xFF).toByte(),
                ((length shr 16) and 0xFF).toByte(),
                ((length shr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte(),
            )
        }
    }
}
