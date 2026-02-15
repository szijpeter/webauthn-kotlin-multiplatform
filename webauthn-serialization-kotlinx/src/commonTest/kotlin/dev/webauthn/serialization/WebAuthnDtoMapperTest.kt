package dev.webauthn.serialization

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class WebAuthnDtoMapperTest {
    @Test
    fun creationOptionsRejectInvalidRpId() {
        val dto = PublicKeyCredentialCreationOptionsDto(
            rp = RpEntityDto(id = "Example.COM", name = "Example"),
            user = UserEntityDto(
                id = "YWFhYWFhYWFhYWFhYWFhYQ",
                name = "alice",
                displayName = "Alice",
            ),
            challenge = "YWFhYWFhYWFhYWFhYWFhYQ",
            pubKeyCredParams = listOf(PublicKeyCredentialParametersDto(type = "public-key", alg = -7)),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationResponseParsesAuthenticatorDataFields() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val authenticatorData = authenticatorDataBytes(
            rpIdHash = ByteArray(32) { 0x22 },
            flags = 0x05,
            signCount = 42,
        )
        val dto = AuthenticationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                authenticatorData = Base64UrlBytes.fromBytes(authenticatorData).encoded(),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)).encoded(),
                userHandle = null,
            ),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Valid)
        assertEquals(0x05, result.value.authenticatorData.flags)
        assertEquals(42, result.value.authenticatorData.signCount)
        assertContentEquals(ByteArray(32) { 0x22 }, result.value.authenticatorData.rpIdHash)
    }

    @Test
    fun authenticationResponseRejectsTruncatedAuthenticatorData() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val dto = AuthenticationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                authenticatorData = Base64UrlBytes.fromBytes(ByteArray(10) { 1 }).encoded(),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)).encoded(),
            ),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationResponseRejectsInvalidUserHandle() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val authenticatorData = authenticatorDataBytes(
            rpIdHash = ByteArray(32) { 0x22 },
            flags = 0x01,
            signCount = 7,
        )
        val dto = AuthenticationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                authenticatorData = Base64UrlBytes.fromBytes(authenticatorData).encoded(),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)).encoded(),
                userHandle = "bad*",
            ),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationResponseExtractsAuthDataFromAttestationObject() {
        val credentialBytes = ByteArray(16) { 0x33 }
        val credentialId = CredentialId.fromBytes(credentialBytes)
        val cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02)
        val authData = registrationAuthenticatorDataBytes(
            rpIdHash = ByteArray(32) { 0x44 },
            flags = 0x41,
            signCount = 9,
            credentialId = credentialBytes,
            cosePublicKey = cosePublicKey,
        )
        val attestationObject = attestationObjectWithAuthData(authData)
        val dto = RegistrationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = RegistrationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)).encoded(),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
            ),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Valid)
        assertEquals(9, result.value.rawAuthenticatorData.signCount)
        assertEquals(0x41, result.value.rawAuthenticatorData.flags)
        assertEquals(credentialId.value.encoded(), result.value.attestedCredentialData.credentialId.value.encoded())
        assertContentEquals(cosePublicKey, result.value.attestedCredentialData.cosePublicKey)
    }

    @Test
    fun authenticationResponseParsesExtensions() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
        val authenticatorData = authenticatorDataBytes(
            rpIdHash = ByteArray(32) { 0x22 },
            flags = 0x01,
            signCount = 10,
        )
        val dto = AuthenticationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                authenticatorData = Base64UrlBytes.fromBytes(authenticatorData).encoded(),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)).encoded(),
            ),
            clientExtensionResults = AuthenticationExtensionsClientOutputsDto(
                prf = PrfExtensionOutputDto(
                    enabled = true,
                    results = PrfValuesDto(
                        first = Base64UrlBytes.fromBytes(byteArrayOf(0xAA.toByte())).encoded(),
                    )
                )
            )
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Valid)
        val extensions = result.value.extensions
        assertNotNull(extensions)
        assertNotNull(extensions.prf)
        assertTrue(extensions.prf!!.enabled!!)
        assertNotNull(extensions.prf!!.results)
        assertContentEquals(byteArrayOf(0xAA.toByte()), extensions.prf!!.results!!.first)

        // Round trip
        val backToDto = WebAuthnDtoMapper.fromModel(result.value)
        assertEquals(dto.clientExtensionResults?.prf?.enabled, backToDto.clientExtensionResults?.prf?.enabled)
        assertEquals(dto.clientExtensionResults?.prf?.results?.first, backToDto.clientExtensionResults?.prf?.results?.first)
    }

    @Test
    fun registrationResponseRejectsAttestationWithoutAuthData() {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x33 })
        val attestationObject = cborMap(
            "fmt" to cborText("none"),
            "attStmt" to cborMap(),
        )
        val dto = RegistrationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = RegistrationResponsePayloadDto(
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)).encoded(),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
            ),
        )

        val result = WebAuthnDtoMapper.toModel(dto)
        assertTrue(result is ValidationResult.Invalid)
    }

    private fun authenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
    ): ByteArray {
        return concat(
            rpIdHash,
            byteArrayOf(flags.toByte()),
            uint32(signCount),
        )
    }

    private fun registrationAuthenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
    ): ByteArray {
        return concat(
            rpIdHash,
            byteArrayOf(flags.toByte()),
            uint32(signCount),
            ByteArray(16) { 0x55 },
            uint16(credentialId.size),
            credentialId,
            cosePublicKey,
        )
    }

    private fun attestationObjectWithAuthData(authData: ByteArray): ByteArray {
        return cborMap(
            "fmt" to cborText("none"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(),
        )
    }

    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        entries.forEach { (key, value) ->
            result = concat(result, cborText(key), value)
        }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return concat(cborHeader(majorType = 3, length = bytes.size), bytes)
    }

    private fun cborBytes(value: ByteArray): ByteArray {
        return concat(cborHeader(majorType = 2, length = value.size), value)
    }

    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        require(length >= 0)
        return when {
            length < 24 -> byteArrayOf(((majorType shl 5) or length).toByte())
            length <= 0xFF -> byteArrayOf(((majorType shl 5) or 24).toByte(), length.toByte())
            length <= 0xFFFF -> byteArrayOf(
                ((majorType shl 5) or 25).toByte(),
                ((length ushr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte(),
            )

            else -> byteArrayOf(
                ((majorType shl 5) or 26).toByte(),
                ((length ushr 24) and 0xFF).toByte(),
                ((length ushr 16) and 0xFF).toByte(),
                ((length ushr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte(),
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
        val size = chunks.sumOf { it.size }
        val result = ByteArray(size)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(result, destinationOffset = offset)
            offset += chunk.size
        }
        return result
    }
}
