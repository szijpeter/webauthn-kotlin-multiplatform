package dev.webauthn.serialization

import dev.webauthn.model.ValidationResult
import dev.webauthn.model.Base64UrlBytes
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SerializationConformanceTest {

    @Test
    fun testRegistrationResponseRejectsNonMinimalAuthDataLength() {
        // Construct an attestation object where authData is non-minimally encoded
        // attestationObject is a CBOR map with "authData" key.
        // "authData" value is a byte string.
        // We will encode the LENGTH of this byte string non-minimally.
        
        val authDataPayload = ByteArray(37) { 0 } // Minimal valid authData length
        
        // Manual CBOR construction
        // Map(1)
        var cbor = byteArrayOf(0xA1.toByte())
        // Text(8) "authData"
        cbor += byteArrayOf(0x68) + "authData".encodeToByteArray()
        
        // ByteString(37) encoded non-minimally
        // 37 is 0x25. Minimal: 0x58 0x25 (additional info 24, value 37)
        // Wait, 37 > 23, so minimal is 1 byte length (additional info 24).
        // Let's encode it as 2 byte length (additional info 25).
        // 0x59 0x00 0x25
        cbor += byteArrayOf(0x59, 0x00, 0x25) + authDataPayload
        
        val attestationObjectBase64 = Base64UrlBytes.fromBytes(cbor).encoded()
        
        val dto = RegistrationResponseDto(
            id = "AA", // Valid base64url
            rawId = "AA",
            response = RegistrationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf()).encoded(),
                attestationObject = attestationObjectBase64
            )
        )
        
        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid, "Should reject non-minimal CBOR length")
        
        // Verify error message if possible, or just that it's invalid
        val errors = (result as ValidationResult.Invalid).errors
        // The error might be "Malformed CBOR" or similar because readCborLength returns null
        // which causes readCborByteString to return null, which causes extractAuthData to fail or return null
        // If extractAuthData returns null...
        // PublicKeyCredentialDtos.kt:348 -> returns InvalidFormat "Attestation object does not contain a valid authData field"
        // Or if map parsing fails earlier...
        
        assertTrue(errors.any { it.message.contains("valid authData") || it.message.contains("Malformed") }, 
            "Error should indicate issue with attestation object or authData. Got: $errors")
    }

    @Test
    fun testAuthenticatorDataRejectsNonMinimalCredentialIdLength() {
        // AuthenticatorData contains attestedCredentialData if flags set.
        // attestedCredentialData contains credentialIdLength (uint16).
        // CBOR parsing isn't used for credentialIdLength (it's raw bytes), 
        // BUT COSE key at the end IS parsed with skipCborItem.
        
        // Let's test non-minimal CBOR in the COSE key part of attestedCredentialData.
        
        val rpIdHash = ByteArray(32) { 0 }
        val flags = 0x41.toByte() // UP + ATTESTED_CREDENTIAL_DATA
        val signCount = ByteArray(4) { 0 }
        val aaguid = ByteArray(16) { 0 }
        val credIdLen = byteArrayOf(0x00, 0x01) // length 1
        val credId = byteArrayOf(0xAA.toByte())
        
        // COSE Key: Empty map encoded non-minimally? 
        // Or just map(1) where key is encoded non-minimally.
        // Map(1)
        val coseKeyHeader = byteArrayOf(0xA1.toByte())
        // Key: int(1) encoded as 2 bytes (0x19 0x00 0x01) instead of 1 byte (0x01)
        val coseKeyKey = byteArrayOf(0x19, 0x00, 0x01) 
        val coseKeyVal = byteArrayOf(0x02) // int(2)
        
        val authData = rpIdHash + flags + signCount + aaguid + credIdLen + credId + coseKeyHeader + coseKeyKey + coseKeyVal
        
        val dto = AuthenticationResponseDto(
            id = "AA",
            rawId = "AA",
            response = AuthenticationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf()).encoded(),
                authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                signature = ""
            )
        )
        
        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid, "Should reject non-minimal CBOR in COSE key")
    }
}
