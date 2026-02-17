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
        // Construct valid AuthorizationList (swEnforced)
        val validTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256 (0x0100)
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
            derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), // Version
            derInteger(byteArrayOf(0)), // SecurityLevel
            derInteger(byteArrayOf(0)), // KeymasterVersion
            derInteger(byteArrayOf(0)), // KeymasterSecurityLevel
            derOctetString(clientDataHash), // Challenge
            derOctetString(ByteArray(0)), // UniqueId
            validTags, // swEnforced
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
        assertTrue(result is ValidationResult.Valid, "Expected Valid, got $result")
    }

    @Test
    fun verifyPassesWithTrustAnchorValidation() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        
        // Construct valid AuthorizationList (swEnforced)
        val validTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
            derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), validTags, derSequence()
        )
        val extensionValue = derOctetString(extensionValueSeq)
        val attCert = generateAttestationCert(kp, extensionValue)
        
        // Use the cert itself as the trust anchor
        val trustSource = dev.webauthn.crypto.TrustAnchorSource { _ -> listOf(attCert) }
        
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)

        val attestationObject = buildAndroidKeyAttestationObject(
            authData = authData,
            alg = -7,
            sig = sig,
            x5c = listOf(attCert),
        )

        val verifier = AndroidKeyAttestationStatementVerifier(trustAnchorSource = trustSource)
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)

        val result = verifier.verify(input)
        assertTrue(result is ValidationResult.Valid, "Expected Valid with trust anchor, got $result")
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
            derSequence(
                derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
                derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
                derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
                derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
                derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
                derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
            ),
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
            derSequence(
                derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
                derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
                derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
                derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
                derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
                derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
            ), // swEnforced with valid tags
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
            derSequence(
                derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
                derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
                derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
                derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
                derTag(0xAA, derInteger(byteArrayOf(1))) // Curve: P-256
                // Missing Origin in swEnforced, present in teeEnforced as bad value
            ), // swEnforced
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

    @Test
    fun verifyFailsForWrongFmt() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        
        // Use "packed" format but with android-key structure
        val attestationObject = cborMap(
            "fmt" to cborText("packed"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "alg" to cborInt(-7),
                "sig" to cborBytes(ByteArray(64)),
                "x5c" to cborArray(listOf(cborBytes(ByteArray(0))))
            )
        )

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("Format must be android-key"))
    }

    @Test
    fun verifyFailsForMissingExtension() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        // Generate cert WITHOUT extension (pass null)
        val attCert = generateAttestationCert(kp, null)
        
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        val error = (result as ValidationResult.Invalid).errors.first()
        assertTrue(error.message.contains("Android Key Attestation extension missing"))
    }

    @Test
    fun verifyFailsForInvalidSignature() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        
        // Generate valid cert
        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(sha256(clientDataJson)), derOctetString(ByteArray(0)), derSequence(
                derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
                derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
                derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
                derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
                derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
                derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
            ), derSequence()
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        // Use garbage signature
        val sig = ByteArray(64) { 0xFF.toByte() }
        
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.any { it.message.contains("Invalid signature") || it.message.contains("Signature verification error") })
    }

    @Test
    fun verifyFailsForMissingAlg() {
         val authData = sampleAuthDataBytes()
         val attestationObject = cborMap(
            "fmt" to cborText("android-key"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                // "alg" missing
                "sig" to cborBytes(ByteArray(64)),
                "x5c" to cborArray(listOf(cborBytes(ByteArray(0))))
            )
        )
        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), ByteArray(0), attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("alg, sig, and x5c are required"))
    }

     @Test
    fun verifyFailsForMissingX5c() {
         val authData = sampleAuthDataBytes()
         val attestationObject = cborMap(
            "fmt" to cborText("android-key"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(
                "alg" to cborInt(-7),
                "sig" to cborBytes(ByteArray(64))
                // "x5c" missing
            )
        )
        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(CredentialId.fromBytes(ByteArray(16)), ByteArray(0), attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("alg, sig, and x5c are required"))
    }


    @Test
    fun verifyFailsWhenKeyPurposeWrong() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        // Purpose: VERIFY (1) instead of SIGN (2)
        val wrongPurposeTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(1)))), // VERIFY
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
            derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), wrongPurposeTags, derSequence()
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, authData + clientDataHash)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("Key purpose does not contain SIGN"))
    }

    @Test
    fun verifyFailsWhenAlgorithmWrong() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        // Alg: RSA (1) instead of EC (3)
        val wrongAlgTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(1))), // Alg: RSA
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256 (matches EC but wrong alg)
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256 (shouldn't be here for RSA but logic might ignore or check consistency)
            derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), wrongAlgTags, derSequence()
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, authData + clientDataHash)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("Attestation alg 1 does not match EC key"))
    }

    @Test
    fun verifyFailsWhenKeySizeWrong() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        // KeySize: 384 instead of 256
        val wrongSizeTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0x80.toByte()))), // KeySize: 384 (0x0180)
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
            derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), wrongSizeTags, derSequence()
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, authData + clientDataHash)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("Attestation key size 384 != 256"))
    }

    @Test
    fun verifyFailsWhenDigestWrong() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        // Digest: SHA1 (2) instead of SHA256 (4)
        val wrongDigestTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
            derTag(0xA5, derSet(derInteger(byteArrayOf(2)))), // Digest: SHA-1
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
            derTag(0xBF853E, derInteger(byteArrayOf(0))) // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), wrongDigestTags, derSequence()
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, authData + clientDataHash)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)
        
        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("Key digest does not contain SHA-256"))
    }

    @Test
    fun verifyFailsWhenDigestMissing() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        val missingDigestTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
            derTag(0xBF853E, derInteger(byteArrayOf(0))), // Origin: GENERATED
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), missingDigestTags, derSequence(),
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, authData + clientDataHash)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("Key digest missing"))
    }

    @Test
    fun verifyFailsWhenOriginMissing() {
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)

        val missingOriginTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))), // Purpose: SIGN
            derTag(0xA2, derInteger(byteArrayOf(3))), // Alg: EC
            derTag(0xA3, derInteger(byteArrayOf(1, 0))), // KeySize: 256
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))), // Digest: SHA-256
            derTag(0xAA, derInteger(byteArrayOf(1))), // Curve: P-256
        )

        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), missingOriginTags, derSequence(),
        )
        val attCert = generateAttestationCert(kp, derOctetString(extensionValueSeq))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, authData + clientDataHash)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))

        val verifier = AndroidKeyAttestationStatementVerifier()
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
        assertTrue((result as ValidationResult.Invalid).errors.first().message.contains("Key origin missing"))
    }

    @Test
    fun sharedCryptoServices_noRegressionInValidAndInvalidCases() {
        val verifier = AndroidKeyAttestationStatementVerifier(
            digestService = JvmDigestService(),
            certificateSignatureVerifier = JvmCertificateSignatureVerifier(),
            certificateInspector = JvmCertificateInspector(),
            certificateChainValidator = JvmCertificateChainValidator(),
            cosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
        )
        val kp = generateES256KeyPair()
        val authData = sampleAuthDataBytes()
        val clientDataJson = """{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}""".toByteArray()
        val clientDataHash = sha256(clientDataJson)
        val validTags = derSequence(
            derTag(0xA1, derSet(derInteger(byteArrayOf(2)))),
            derTag(0xA2, derInteger(byteArrayOf(3))),
            derTag(0xA3, derInteger(byteArrayOf(1, 0))),
            derTag(0xA5, derSet(derInteger(byteArrayOf(4)))),
            derTag(0xAA, derInteger(byteArrayOf(1))),
            derTag(0xBF853E, derInteger(byteArrayOf(0))),
        )
        val extensionValueSeq = derSequence(
            derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)), derInteger(byteArrayOf(0)),
            derOctetString(clientDataHash), derOctetString(ByteArray(0)), validTags, derSequence(),
        )
        val extensionValue = derOctetString(extensionValueSeq)
        val attCert = generateAttestationCert(kp, extensionValue)
        val signatureBase = authData + clientDataHash
        val sig = signES256(kp.private as java.security.interfaces.ECPrivateKey, signatureBase)
        val attestationObject = buildAndroidKeyAttestationObject(authData, -7, sig, listOf(attCert))
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val input = sampleInput(credentialId, clientDataJson, attestationObject, authData)
        assertTrue(verifier.verify(input) is ValidationResult.Valid)

        val badSigAttestation = buildAndroidKeyAttestationObject(authData, -7, ByteArray(64) { 0x00 }, listOf(attCert))
        val invalidInput = sampleInput(credentialId, clientDataJson, badSigAttestation, authData)
        val invalidResult = verifier.verify(invalidInput)
        assertTrue(invalidResult is ValidationResult.Invalid)
        assertTrue((invalidResult as ValidationResult.Invalid).errors.any { it.message.contains("Invalid signature") })
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
        cosePublicKey: ByteArray = validCoseEcKeyBytes(),
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
                attestedCredentialData = AttestedCredentialData(ByteArray(16), credentialId, cosePublicKey)
            ),
            clientData = CollectedClientData("webauthn.create", Challenge.fromBytes(ByteArray(16){1}), Origin.parseOrThrow("https://example.com")),
            expectedOrigin = Origin.parseOrThrow("https://example.com"),
        )
    }

    private fun validCoseEcKeyBytes(): ByteArray {
        val x = ByteArray(32) { 0x01 }
        val y = ByteArray(32) { 0x02 }
        return cborMapInt(
            1L to 2L, // kty: EC2
            3L to -7L, // alg: ES256
            -1L to 1L, // crv: P-256
            -2L to x,
            -3L to y
        )
    }

    private fun cborMapInt(vararg entries: Pair<Long, Any>): ByteArray {
        var res = cborHeader(5, entries.size)
        entries.forEach { (k,v) -> 
            res = concat(res, cborInt(k))
            res = when(v) {
                is Long -> concat(res, cborInt(v))
                is Int -> concat(res, cborInt(v.toLong()))
                is ByteArray -> concat(res, cborBytes(v))
                else -> throw IllegalArgumentException("Unsupported value type")
            }
        }
        return res
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
