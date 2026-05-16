package dev.webauthn.serialization

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.Origin
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProtocolParsersGoldenTest {
    @Test
    fun parseCollectedClientDataJsonExtractsExpectedFields() {
        val rawJson = """
            {
              "type": "webauthn.get",
              "challenge": "JpE2XdxmrNqpe1loYEcfm8K_oZfAkE1ZSwEIuMEOBOA",
              "origin": "android:apk-key-hash:Vbj-mPe9x0NEiHDGG3EOi04ETGT5SIoEc3f2zpc7qC8",
              "crossOrigin": false,
              "androidPackageName": "dev.webauthn.samples.composepasskey.android"
            }
        """.trimIndent().encodeToByteArray()

        val result = parseCollectedClientDataJson(rawJson)

        assertTrue(result is ValidationResult.Valid)
        assertEquals("webauthn.get", result.value.type)
        assertEquals(
            Challenge.parseOrThrow("JpE2XdxmrNqpe1loYEcfm8K_oZfAkE1ZSwEIuMEOBOA"),
            result.value.challenge,
        )
        assertEquals(
            Origin.parseOrThrow("android:apk-key-hash:Vbj-mPe9x0NEiHDGG3EOi04ETGT5SIoEc3f2zpc7qC8"),
            result.value.origin,
        )
        assertEquals(false, result.value.crossOrigin)
    }

    @Test
    fun parseCollectedClientDataJsonRejectsMalformedJsonAndInvalidFieldTypes() {
        val malformed = parseCollectedClientDataJson("{".encodeToByteArray())
        val invalidCrossOrigin = parseCollectedClientDataJson(
            """
                {
                  "type": "webauthn.get",
                  "challenge": "JpE2XdxmrNqpe1loYEcfm8K_oZfAkE1ZSwEIuMEOBOA",
                  "origin": "https://example.com",
                  "crossOrigin": "nope"
                }
            """.trimIndent().encodeToByteArray(),
        )

        assertTrue(malformed is ValidationResult.Invalid)
        assertTrue(invalidCrossOrigin is ValidationResult.Invalid)
    }

    @Test
    fun parseCollectedClientDataJsonRejectsMissingChallenge() {
        val result = parseCollectedClientDataJson(
            """
                {
                  "type": "webauthn.create",
                  "origin": "https://example.com"
                }
            """.trimIndent().encodeToByteArray(),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("clientDataJSON.challenge", result.errors.single().field)
    }

    @Test
    fun parseCollectedClientDataJsonRejectsExplicitNullRequiredFieldAsTypeError() {
        val result = parseCollectedClientDataJson(
            """
                {
                  "type": "webauthn.create",
                  "challenge": null,
                  "origin": "https://example.com"
                }
            """.trimIndent().encodeToByteArray(),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("clientDataJSON", result.errors.single().field)
        assertEquals("clientDataJSON must use valid JSON field types", result.errors.single().message)
    }

    @Test
    fun parseCollectedClientDataJsonPreservesExactTypeChallengeAndOriginValues() {
        val result = parseCollectedClientDataJson(
            """
                {
                  "type": "webauthn.create",
                  "challenge": "LA5DLbYCrdcg0MuKTxH5hiR5eHWTQF6ObjeAzvvlcrI",
                  "origin": "https://example.com"
                }
            """.trimIndent().encodeToByteArray(),
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals("webauthn.create", result.value.type)
        assertEquals(Challenge.parseOrThrow("LA5DLbYCrdcg0MuKTxH5hiR5eHWTQF6ObjeAzvvlcrI"), result.value.challenge)
        assertEquals(Origin.parseOrThrow("https://example.com"), result.value.origin)
    }

    @Test
    fun parseAuthenticatorDataExtractsFlagsAndAttestedCredentialData() {
        val credentialId = Base64UrlBytes.parseOrThrow("adnJdzQQOzHT8aobzfRCfA").bytes()
        val coseKey = Base64UrlBytes.parseOrThrow(
            "pQECAyYgASFYIHflyS-aHVhwAzewMoOb5NS3wrABqgvYKVxzLYLXoRY6IlggJ5K-fCUDYnGk0SH-8wC05tBuSYdQUk45X4tBxNOSMgw",
        ).bytes()
        val result = parseAuthenticatorData(
            bytes = registrationAuthenticatorDataBytes(
                rpIdHash = Base64UrlBytes.parseOrThrow("1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWo").bytes(),
                flags = 0xDD,
                signCount = 7,
                credentialId = credentialId,
                cosePublicKey = coseKey,
                extensionData = cborMap(cborText("credProps") to cborMap(cborText("rk") to byteArrayOf(0xF5.toByte()))),
            ),
            field = "authenticatorData",
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals(0xDD, result.value.authenticatorData.flags)
        assertEquals(7L, result.value.authenticatorData.signCount)
        assertContentEquals(
            Base64UrlBytes.parseOrThrow("1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWo").bytes(),
            result.value.authenticatorData.rpIdHash.bytes(),
        )
        assertEquals("adnJdzQQOzHT8aobzfRCfA", result.value.attestedCredentialData?.credentialId?.value?.encoded())
        assertEquals(
            "6puNZk0BHSE85La0jLV11A",
            result.value.attestedCredentialData?.aaguid?.bytes()?.let { Base64UrlBytes.fromBytes(it).encoded() },
        )
        assertContentEquals(coseKey, result.value.attestedCredentialData?.cosePublicKey?.bytes())
        assertNotNull(result.value.extensionDataBytes)
    }

    @Test
    fun parseAuthenticatorDataSupportsExtensionsWithoutAttestedCredentialData() {
        val result = parseAuthenticatorData(
            bytes = authenticatorDataBytes(
                rpIdHash = Base64UrlBytes.parseOrThrow("1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWo").bytes(),
                flags = FLAG_EXTENSION_DATA_INCLUDED or 0x01,
                signCount = 0,
                extensionData = cborMap(cborText("txAuthSimple") to cborText("ok")),
            ),
            field = "response.authenticatorData",
        )

        assertTrue(result is ValidationResult.Valid)
        assertNull(result.value.attestedCredentialData)
        assertNotNull(result.value.extensionDataBytes)
    }

    @Test
    fun parseAuthenticatorDataRejectsMalformedCoseAndTrailingBytes() {
        val malformedCose = parseAuthenticatorData(
            bytes = registrationAuthenticatorDataBytes(
                rpIdHash = ByteArray(32) { 0x11 },
                flags = FLAG_ATTESTED_CREDENTIAL_DATA or 0x01,
                signCount = 1,
                credentialId = ByteArray(16) { 0x22 },
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01),
                extensionData = null,
            ),
            field = "attestationObject.authData",
        )
        val trailingBytes = parseAuthenticatorData(
            bytes = authenticatorDataBytes(
                rpIdHash = ByteArray(32) { 0x33 },
                flags = 0x01,
                signCount = 1,
                extensionData = byteArrayOf(0x00),
            ),
            field = "response.authenticatorData",
        )

        assertTrue(malformedCose is ValidationResult.Invalid)
        assertTrue(trailingBytes is ValidationResult.Invalid)
    }

    @Test
    fun parseAuthenticatorDataRejectsNonMapCosePublicKey() {
        val result = parseAuthenticatorData(
            bytes = registrationAuthenticatorDataBytes(
                rpIdHash = ByteArray(32) { 0x11 },
                flags = FLAG_ATTESTED_CREDENTIAL_DATA or 0x01,
                signCount = 1,
                credentialId = ByteArray(16) { 0x22 },
                cosePublicKey = cborText("not-a-cose-key"),
                extensionData = null,
            ),
            field = "attestationObject.authData",
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("COSE public key must be a CBOR map", result.errors.single().message)
    }

    @Test
    fun parseAuthenticatorDataRejectsNonMapExtensionData() {
        val result = parseAuthenticatorData(
            bytes = authenticatorDataBytes(
                rpIdHash = ByteArray(32) { 0x33 },
                flags = FLAG_EXTENSION_DATA_INCLUDED or 0x01,
                signCount = 1,
                extensionData = cborText("not-an-extension-map"),
            ),
            field = "response.authenticatorData",
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("Extension data must be a CBOR map", result.errors.single().message)
    }

    private fun authenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
        extensionData: ByteArray?,
    ): ByteArray {
        var result = rpIdHash + byteArrayOf(flags.toByte()) + uint32(signCount)
        if (extensionData != null) {
            result += extensionData
        }
        return result
    }

    private fun registrationAuthenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
        extensionData: ByteArray?,
    ): ByteArray {
        var result = rpIdHash + byteArrayOf(flags.toByte()) + uint32(signCount)
        result += Base64UrlBytes.parseOrThrow("6puNZk0BHSE85La0jLV11A").bytes()
        result += uint16(credentialId.size)
        result += credentialId
        result += cosePublicKey
        if (extensionData != null) {
            result += extensionData
        }
        return result
    }

    private fun cborMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        entries.forEach { (key, value) -> result += key + value }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return cborHeader(3, bytes.size) + bytes
    }

    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        require(length < 24) { "Test helper only supports short lengths" }
        return byteArrayOf(((majorType shl 5) or length).toByte())
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
}
