package dev.webauthn.serialization

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SerializationConformanceTest {

    @Test
    fun registrationResponseParsesAuthDataFromTypedCborAttestationObject() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val cosePublicKey = validEc2CoseKey()
        val authData = registrationAuthenticatorDataBytes(
            credentialId = credentialId.value.bytes(),
            cosePublicKey = cosePublicKey,
        )
        val dto = registrationResponseDto(
            credentialId = credentialId,
            attestationObject = attestationObjectWithAuthData(authData),
        )

        val result = WebAuthnDtoMapper.toModel(dto)

        assertTrue(result is ValidationResult.Valid)
        assertContentEquals(authData.copyOfRange(0, 32), result.value.rawAuthenticatorData.rpIdHash.bytes())
        assertEquals(credentialId, result.value.attestedCredentialData.credentialId)
        assertContentEquals(cosePublicKey, result.value.attestedCredentialData.cosePublicKey.bytes())
    }

    @Test
    fun registrationResponseIgnoresUnknownTopLevelAttestationKeys() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x22 })
        val authData = registrationAuthenticatorDataBytes(
            credentialId = credentialId.value.bytes(),
            cosePublicKey = validEc2CoseKey(),
        )
        val attestationObject = cborStringMap(
            "fmt" to cborText("none"),
            "authData" to cborBytes(authData),
            "dummy" to cborFloat16Zero(),
            "attStmt" to cborStringMap(),
        )
        val dto = registrationResponseDto(credentialId = credentialId, attestationObject = attestationObject)

        val result = WebAuthnDtoMapper.toModel(dto)

        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun registrationResponseRejectsMalformedAttestationObject() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x33 })
        val dto = registrationResponseDto(
            credentialId = credentialId,
            attestationObject = byteArrayOf(0xA2.toByte(), 0x63, 0x66, 0x6D, 0x74),
        )

        val result = WebAuthnDtoMapper.toModel(dto)

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationResponseRejectsNonMinimalAuthDataLengthEncoding() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x44 })
        val authData = ByteArray(37) { 0x00 }
        val attestationObject = cborStringMap(
            "fmt" to cborText("none"),
            "authData" to cborBytesNonMinimalTwoByteLength(authData),
            "attStmt" to cborStringMap(),
        )
        val dto = registrationResponseDto(credentialId = credentialId, attestationObject = attestationObject)

        val result = WebAuthnDtoMapper.toModel(dto)

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationResponseRejectsMalformedEmbeddedCoseKey() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x55 })
        val malformedCoseKey = byteArrayOf(
            0xA1.toByte(),
            0x01,
        )
        val authData = registrationAuthenticatorDataBytes(
            credentialId = credentialId.value.bytes(),
            cosePublicKey = malformedCoseKey,
        )
        val dto = registrationResponseDto(
            credentialId = credentialId,
            attestationObject = attestationObjectWithAuthData(authData),
        )

        val result = WebAuthnDtoMapper.toModel(dto)

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationResponseRejectsNonMinimalEmbeddedCoseKeyEncoding() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x66 })
        val nonMinimalCoseKey = cborEncodedKeyMap(
            cborIntNonMinimalTwoByteLength(1L) to cborInt(2L),
        )
        val authData = registrationAuthenticatorDataBytes(
            credentialId = credentialId.value.bytes(),
            cosePublicKey = nonMinimalCoseKey,
        )
        val dto = registrationResponseDto(
            credentialId = credentialId,
            attestationObject = attestationObjectWithAuthData(authData),
        )

        val result = WebAuthnDtoMapper.toModel(dto)

        assertTrue(result is ValidationResult.Invalid)
    }

    private fun registrationResponseDto(
        credentialId: CredentialId,
        attestationObject: ByteArray,
    ): RegistrationResponseDto {
        return RegistrationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = RegistrationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(0x01, 0x02, 0x03)).encoded(),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
            ),
        )
    }

    private fun registrationAuthenticatorDataBytes(
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
    ): ByteArray {
        return concat(
            ByteArray(32) { 0x22.toByte() },
            byteArrayOf(0x41.toByte()),
            uint32(7),
            ByteArray(16) { 0x55.toByte() },
            uint16(credentialId.size),
            credentialId,
            cosePublicKey,
        )
    }

    private fun attestationObjectWithAuthData(authData: ByteArray): ByteArray {
        return cborStringMap(
            "fmt" to cborText("none"),
            "authData" to cborBytes(authData),
            "attStmt" to cborStringMap(),
        )
    }

    private fun validEc2CoseKey(): ByteArray {
        return cborEncodedKeyMap(
            cborInt(1L) to cborInt(2L),
            cborInt(3L) to cborInt(-7L),
            cborInt(-1L) to cborInt(1L),
            cborInt(-2L) to cborBytes(ByteArray(32) { 0x11.toByte() }),
            cborInt(-3L) to cborBytes(ByteArray(32) { 0x22.toByte() }),
        )
    }

    private fun cborStringMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        entries.forEach { (key, value) ->
            result += cborText(key) + value
        }
        return result
    }

    private fun cborEncodedKeyMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        entries.forEach { (key, value) ->
            result += key + value
        }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val encoded = value.encodeToByteArray()
        return cborHeader(majorType = 3, length = encoded.size) + encoded
    }

    private fun cborBytes(value: ByteArray): ByteArray = cborHeader(majorType = 2, length = value.size) + value

    private fun cborBytesNonMinimalTwoByteLength(value: ByteArray): ByteArray {
        return byteArrayOf(0x59, 0x00, value.size.toByte()) + value
    }

    private fun cborInt(value: Long): ByteArray {
        return if (value >= 0) {
            cborHeaderLong(majorType = 0, value = value)
        } else {
            cborHeaderLong(majorType = 1, value = -1L - value)
        }
    }

    private fun cborIntNonMinimalTwoByteLength(value: Long): ByteArray {
        require(value in 0..255)
        return byteArrayOf(0x19, 0x00, value.toByte())
    }

    private fun cborFloat16Zero(): ByteArray = byteArrayOf(0xF9.toByte(), 0x00, 0x00)

    private fun cborHeader(majorType: Int, length: Int): ByteArray = cborHeaderLong(majorType, length.toLong())

    private fun cborHeaderLong(majorType: Int, value: Long): ByteArray {
        val prefix = majorType shl 5
        return when {
            value < 24 -> byteArrayOf((prefix or value.toInt()).toByte())
            value < 256 -> byteArrayOf((prefix or 24).toByte(), value.toByte())
            value < 65536 -> byteArrayOf(
                (prefix or 25).toByte(),
                (value shr 8).toByte(),
                value.toByte(),
            )

            else -> byteArrayOf(
                (prefix or 26).toByte(),
                (value shr 24).toByte(),
                (value shr 16).toByte(),
                (value shr 8).toByte(),
                value.toByte(),
            )
        }
    }

    private fun uint16(value: Int): ByteArray {
        return byteArrayOf(
            ((value ushr 8) and 0xFF).toByte(),
            (value and 0xFF).toByte(),
        )
    }

    private fun uint32(value: Long): ByteArray {
        return byteArrayOf(
            ((value ushr 24) and 0xFF).toByte(),
            ((value ushr 16) and 0xFF).toByte(),
            ((value ushr 8) and 0xFF).toByte(),
            (value and 0xFF).toByte(),
        )
    }

    private fun concat(vararg chunks: ByteArray): ByteArray {
        val result = ByteArray(chunks.sumOf { it.size })
        var offset = 0
        chunks.forEach { chunk ->
            chunk.copyInto(result, destinationOffset = offset)
            offset += chunk.size
        }
        return result
    }
}
