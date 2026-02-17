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
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertTrue

class PackedAttestationStatementVerifierTest {

    // ---- Self-attestation tests ----

    @Test
    fun selfAttestationPassesForValidES256Signature() {
        val kp = generateES256KeyPair()
        val cosePublicKey = TestCoseHelpers.coseBytesFromPublicKey(kp.public)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()
        val clientDataHash = sha256(clientDataJson)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        // Self-attestation: alg=-7 (ES256), sig, no x5c
        val attestationObject = buildPackedAttestationObject(
            authData = authData,
            alg = CoseAlgorithm.ES256.code.toLong(),
            sig = sig,
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, cosePublicKey)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Valid, "Expected Valid but got: $result")
    }

    @Test
    fun selfAttestationFailsForSignatureMismatch() {
        val kp = generateES256KeyPair()
        val cosePublicKey = TestCoseHelpers.coseBytesFromPublicKey(kp.public)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()

        val attestationObject = buildPackedAttestationObject(
            authData = authData,
            alg = CoseAlgorithm.ES256.code.toLong(),
            sig = ByteArray(64) { 0xFF.toByte() }, // garbage sig
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, cosePublicKey)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun selfAttestationFailsForAlgorithmMismatch() {
        val kp = generateES256KeyPair()
        val cosePublicKey = TestCoseHelpers.coseBytesFromPublicKey(kp.public)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()
        val clientDataHash = sha256(clientDataJson)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        // Claim RS256 (-257) but key is actually ES256
        val attestationObject = buildPackedAttestationObject(
            authData = authData,
            alg = CoseAlgorithm.RS256.code.toLong(),
            sig = sig,
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, cosePublicKey)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    // ---- Full attestation (x5c) tests ----

    @Test
    fun fullAttestationPassesForValidX5cChain() {
        val kp = generateES256KeyPair()
        val attCert = generateSelfSignedAttestationCert(kp)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()
        val clientDataHash = sha256(clientDataJson)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        val attestationObject = buildPackedAttestationObject(
            authData = authData,
            alg = CoseAlgorithm.ES256.code.toLong(),
            sig = sig,
            x5c = listOf(attCert),
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        // For full attestation, the credential key doesn't matter for sig verification
        val credKey = ByteArray(32) { 0x22 }
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, credKey)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Valid, "Expected Valid but got: $result")
    }

    @Test
    fun fullAttestationFailsForInvalidSignature() {
        val kp = generateES256KeyPair()
        val attCert = generateSelfSignedAttestationCert(kp)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()

        val attestationObject = buildPackedAttestationObject(
            authData = authData,
            alg = CoseAlgorithm.ES256.code.toLong(),
            sig = ByteArray(64) { 0xFF.toByte() }, // invalid sig
            x5c = listOf(attCert),
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, ByteArray(32))
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    // ---- ECDAA rejection ----

    @Test
    fun ecdaaPresenceRejected() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()

        val attestationObject = buildPackedAttestationObjectWithEcdaa(
            authData = authData,
            alg = CoseAlgorithm.ES256.code.toLong(),
            sig = ByteArray(64),
            ecdaaKeyId = ByteArray(16) { 0x01 },
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, ByteArray(32))
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    // ---- Helpers ----

    private fun sampleAuthDataBytes(): ByteArray {
        val rpIdHash = ByteArray(32) { 0x10 }
        val flags = byteArrayOf(0x41) // UP + AT
        val signCount = byteArrayOf(0, 0, 0, 1)
        return rpIdHash + flags + signCount + ByteArray(16) { 0x22 } // aaguid
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

    /**
     * Creates a self-signed X.509v3 certificate with OU=Authenticator Attestation
     * by constructing raw ASN.1/DER bytes. No JDK internal APIs are used.
     */
    private fun generateSelfSignedAttestationCert(keyPair: java.security.KeyPair): ByteArray {
        val subjectPublicKeyInfo = keyPair.public.encoded // SPKI in DER

        // DN: CN=Test Authenticator, OU=Authenticator Attestation, O=Test, C=US
        val rdnSequence = derSequence(
            derSet(derSequence(derOid(OID_COUNTRY), derPrintableString("US"))),
            derSet(derSequence(derOid(OID_ORGANIZATION), derUtf8String("Test"))),
            derSet(derSequence(derOid(OID_ORG_UNIT), derUtf8String("Authenticator Attestation"))),
            derSet(derSequence(derOid(OID_COMMON_NAME), derUtf8String("Test Authenticator"))),
        )

        val serialNumber = derInteger(byteArrayOf(0x01))

        // SHA256withECDSA algorithm identifier: OID 1.2.840.10045.4.3.2
        val sigAlgId = derSequence(derOid(OID_SHA256_WITH_ECDSA))

        // Validity: 2026-01-01 to 2027-01-01 (fixed for deterministic tests)
        val validity = derSequence(
            derUtcTime("260101000000Z"),
            derUtcTime("270101000000Z"),
        )

        // TBSCertificate
        val tbsCert = derSequence(
            derExplicit(0, derInteger(byteArrayOf(0x02))), // version v3
            serialNumber,
            sigAlgId,
            rdnSequence, // issuer = subject (self-signed)
            validity,
            rdnSequence, // subject
            derRaw(subjectPublicKeyInfo), // subjectPublicKeyInfo
        )

        // Sign the TBSCertificate
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(tbsCert)
        val signatureBytes = sig.sign()

        // Full Certificate = SEQUENCE { tbsCert, sigAlgId, BIT STRING(signature) }
        return derSequence(
            derRaw(tbsCert),
            sigAlgId,
            derBitString(signatureBytes),
        )
    }

    // ---- ASN.1/DER helpers ----

    private fun derSequence(vararg items: ByteArray): ByteArray =
        derTag(0x30, concat(*items))

    private fun derSet(vararg items: ByteArray): ByteArray =
        derTag(0x31, concat(*items))

    private fun derInteger(value: ByteArray): ByteArray =
        derTag(0x02, value)

    private fun derOctetString(value: ByteArray): ByteArray =
        derTag(0x04, value)
    
    private fun derBitString(value: ByteArray): ByteArray =
        derTag(0x03, concat(byteArrayOf(0x00), value)) // 0 unused bits

    private fun derOid(encoded: ByteArray): ByteArray =
        derTag(0x06, encoded)

    private fun derUtf8String(value: String): ByteArray =
        derTag(0x0C, value.encodeToByteArray())

    private fun derPrintableString(value: String): ByteArray =
        derTag(0x13, value.encodeToByteArray())

    private fun derUtcTime(value: String): ByteArray =
        derTag(0x17, value.encodeToByteArray())

    private fun derExplicit(tag: Int, content: ByteArray): ByteArray =
        derTag(0xA0 or tag, content)

    private fun derRaw(content: ByteArray): ByteArray = content

    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        val length = derLength(content.size)
        return concat(byteArrayOf(tag.toByte()), length, content)
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

    // Standard OIDs (encoded form)
    private val OID_COMMON_NAME = byteArrayOf(0x55, 0x04, 0x03)            // 2.5.4.3
    private val OID_COUNTRY = byteArrayOf(0x55, 0x04, 0x06)                // 2.5.4.6
    private val OID_ORGANIZATION = byteArrayOf(0x55, 0x04, 0x0A)           // 2.5.4.10
    private val OID_ORG_UNIT = byteArrayOf(0x55, 0x04, 0x0B)               // 2.5.4.11
    // SHA256withECDSA: 1.2.840.10045.4.3.2
    private val OID_SHA256_WITH_ECDSA = byteArrayOf(
        0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02,
    )

    private fun spkiSignatureVerifier(): SignatureVerifier {
        return JvmSignatureVerifier()
    }

    private fun sampleInput(
        credentialId: CredentialId,
        clientDataJson: ByteArray,
        attestationObject: ByteArray,
        authData: ByteArray,
        cosePublicKey: ByteArray,
    ): RegistrationValidationInput {
        return RegistrationValidationInput(
            options = PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(
                    id = RpId.parseOrThrow("example.com"),
                    name = "Example",
                ),
                user = PublicKeyCredentialUserEntity(
                    id = UserHandle.fromBytes(ByteArray(16) { 7 }),
                    name = "alice",
                    displayName = "Alice",
                ),
                challenge = Challenge.fromBytes(ByteArray(16) { 1 }),
                pubKeyCredParams = emptyList(),
            ),
            response = RegistrationResponse(
                credentialId = credentialId,
                clientDataJson = Base64UrlBytes.fromBytes(clientDataJson),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject),
                rawAuthenticatorData = AuthenticatorData(
                    rpIdHash = ByteArray(32),
                    flags = 0x41,
                    signCount = 1,
                ),
                attestedCredentialData = AttestedCredentialData(
                    aaguid = ByteArray(16),
                    credentialId = credentialId,
                    cosePublicKey = cosePublicKey,
                ),
            ),
            clientData = CollectedClientData(
                type = "webauthn.create",
                challenge = Challenge.fromBytes(ByteArray(16) { 1 }),
                origin = Origin.parseOrThrow("https://example.com"),
            ),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    // ---- CBOR builders ----

    private fun buildPackedAttestationObject(
        authData: ByteArray,
        alg: Long,
        sig: ByteArray,
        x5c: List<ByteArray>? = null,
    ): ByteArray {
        val attStmtEntries = mutableListOf<Pair<String, ByteArray>>(
            "alg" to cborInt(alg),
            "sig" to cborBytes(sig),
        )
        if (x5c != null) {
            attStmtEntries.add("x5c" to cborArray(x5c.map { cborBytes(it) }))
        }

        return cborMap(
            "fmt" to cborText("packed"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(*attStmtEntries.toTypedArray()),
        )
    }

    private fun buildPackedAttestationObjectWithEcdaa(
        authData: ByteArray,
        alg: Long,
        sig: ByteArray,
        ecdaaKeyId: ByteArray,
    ): ByteArray {
        return cborMap(
            "fmt" to cborText("packed"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "alg" to cborInt(alg),
                "sig" to cborBytes(sig),
                "ecdaaKeyId" to cborBytes(ecdaaKeyId),
            ),
        )
    }

    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        entries.forEach { (key, value) ->
            result = concat(result, cborText(key), value)
        }
        return result
    }

    private fun cborArray(items: List<ByteArray>): ByteArray {
        var result = cborHeader(majorType = 4, length = items.size)
        items.forEach { result = concat(result, it) }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val encoded = value.encodeToByteArray()
        return concat(cborHeader(majorType = 3, length = encoded.size), encoded)
    }

    private fun cborBytes(value: ByteArray): ByteArray {
        return concat(cborHeader(majorType = 2, length = value.size), value)
    }

    private fun cborInt(value: Long): ByteArray {
        return if (value >= 0) {
            cborUnsignedInt(value)
        } else {
            // Negative: major type 1, value = -1 - n
            val encoded = -1L - value
            cborHeaderLong(majorType = 1, length = encoded)
        }
    }

    private fun cborUnsignedInt(value: Long): ByteArray {
        return cborHeaderLong(majorType = 0, length = value)
    }

    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        return cborHeaderLong(majorType, length.toLong())
    }

    private fun cborHeaderLong(majorType: Int, length: Long): ByteArray {
        val prefix = majorType shl 5
        return when {
            length < 24 -> byteArrayOf((prefix or length.toInt()).toByte())
            length < 256 -> byteArrayOf((prefix or 24).toByte(), length.toByte())
            length < 65536 -> byteArrayOf(
                (prefix or 25).toByte(),
                (length shr 8).toByte(),
                length.toByte(),
            )
            else -> byteArrayOf(
                (prefix or 26).toByte(),
                (length shr 24).toByte(),
                (length shr 16).toByte(),
                (length shr 8).toByte(),
                length.toByte(),
            )
        }
    }

    private fun concat(vararg chunks: ByteArray): ByteArray {
        val size = chunks.sumOf { it.size }
        val result = ByteArray(size)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(result, destinationOffset = offset)
            offset += chunk.size
        }
        return result
    }
    @Test
    fun fullAttestationFailsForAaguidMismatch() {
        val kp = generateES256KeyPair()
        val aaguidInCert = ByteArray(16) { 0xAA.toByte() }
        val attCert = generateAttestationCertWithAaguid(kp, aaguidInCert)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        
        // AuthData has different AAGUID
        val authDataAaguid = ByteArray(16) { 0xBB.toByte() }
        val authData = sampleAuthDataBytesWithAaguid(authDataAaguid)
        
        val clientDataHash = sha256(clientDataJson)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        val attestationObject = buildPackedAttestationObject(
            authData = authData,
            alg = CoseAlgorithm.ES256.code.toLong(),
            sig = sig,
            x5c = listOf(attCert),
        )

        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
        )

        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, ByteArray(32))
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("AAGUID"), "Expected AAGUID error, got: ${error.message}")
    }

    private fun sampleAuthDataBytesWithAaguid(aaguid: ByteArray = ByteArray(16) { 0x22 }): ByteArray {
        val rpIdHash = ByteArray(32) { 0x10 }
        val flags = byteArrayOf(0x41) // UP + AT
        val signCount = byteArrayOf(0, 0, 0, 1)
        return rpIdHash + flags + signCount + aaguid + ByteArray(2) + ByteArray(32) // aaguid + credentialIdLen + credentialId... (dummy tail)
    }

    private fun generateAttestationCertWithAaguid(keyPair: java.security.KeyPair, aaguid: ByteArray): ByteArray {
        val subjectPublicKeyInfo = keyPair.public.encoded
        
        // Extensions
        // 1.3.6.1.4.1.45724.1.1.4
        val aaguidOid = byteArrayOf(0x2B, 0x06, 0x01, 0x04, 0x01, 0x82.toByte(), 0xE5.toByte(), 0x1C, 0x01, 0x01, 0x04)
        // Value: OCTET STRING(aaguid)
        val extValue = derOctetString(aaguid)
        // Extension sequence: OID, OCTET STRING(extValue)
        val extension = derSequence(derOid(aaguidOid), derOctetString(extValue))
        
        val extensions = derSequence(extension)
        val tbsExtensions = derExplicit(3, extensions)

        // DN
        val rdnSequence = derSequence(derSet(derSequence(derOid(OID_ORG_UNIT), derUtf8String("Authenticator Attestation"))))
        
        val tbsCert = derSequence(
            derExplicit(0, derInteger(byteArrayOf(0x02))), // v3
            derInteger(byteArrayOf(0x02)), 
            derSequence(derOid(OID_SHA256_WITH_ECDSA)),
            rdnSequence,
            derSequence(derUtcTime("260101000000Z"), derUtcTime("270101000000Z")),
            rdnSequence,
            derRaw(subjectPublicKeyInfo),
            tbsExtensions
        )
        
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(tbsCert)
        val signatureBytes = sig.sign()

        return derSequence(
            derRaw(tbsCert),
            derSequence(derOid(OID_SHA256_WITH_ECDSA)),
            derBitString(signatureBytes),
        )
    }

    @Test
    fun sharedCryptoServices_noRegressionInValidAndInvalidCases() {
        val verifier = PackedAttestationStatementVerifier(
            signatureVerifier = spkiSignatureVerifier(),
            digestService = JvmDigestService(),
            certificateSignatureVerifier = JvmCertificateSignatureVerifier(),
            certificateInspector = JvmCertificateInspector(),
        )
        val kp = generateES256KeyPair()
        val cosePublicKey = TestCoseHelpers.coseBytesFromPublicKey(kp.public)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val authData = sampleAuthDataBytes()
        val clientDataHash = sha256(clientDataJson)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)
        val attestationObject = buildPackedAttestationObject(authData = authData, alg = CoseAlgorithm.ES256.code.toLong(), sig = sig)
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData, cosePublicKey)
        assertTrue(verifier.verify(input) is ValidationResult.Valid)

        val invalidAttestation = buildPackedAttestationObject(authData = authData, alg = CoseAlgorithm.ES256.code.toLong(), sig = ByteArray(64) { 0xFF.toByte() })
        val invalidInput = sampleInput(credentialId, clientDataJson, invalidAttestation, authData, cosePublicKey)
        assertTrue(verifier.verify(invalidInput) is ValidationResult.Invalid)
    }
}
