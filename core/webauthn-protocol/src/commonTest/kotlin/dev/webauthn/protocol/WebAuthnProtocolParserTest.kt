package dev.webauthn.protocol

import dev.webauthn.model.ValidationResult
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RawAuthenticationResponse
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebAuthnProtocolParserTest {
    @Test
    fun extractsAuthDataFromAttestationObjectWithoutDecodingUnrelatedFields() {
        val authData = ByteArray(37) { index -> index.toByte() }
        val attestationObject = cborMap(
            cborText("fmt") to cborText("none"),
            cborText("authData") to cborBytes(authData),
            cborText("attStmt") to cborMap(),
        )

        val result = WebAuthnProtocolParser.extractAuthenticatorData(attestationObject)

        assertTrue(result is ValidationResult.Valid)
        assertContentEquals(authData, result.value)
    }

    @Test
    fun rejectsAttestationObjectWithoutAuthData() {
        val result = WebAuthnProtocolParser.extractAuthenticatorData(
            cborMap(cborText("fmt") to cborText("none")),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("attestationObject", result.errors.single().field)
    }

    @Test
    fun rejectsAuthenticatorDataWithUnexpectedTrailingBytes() {
        val bytes = ByteArray(38).also { it[32] = 0x01 }

        val result = WebAuthnProtocolParser.parseAuthenticatorData(bytes)

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("Unexpected trailing bytes after authenticator data", result.errors.single().message)
    }

    @Test
    fun parsesRawAuthenticationResponseWithoutDependingOnJsonRepresentation() {
        val authenticatorData = ByteArray(37).also { it[32] = 0x01 }
        val raw = RawAuthenticationResponse(
            credentialId = CredentialId.fromBytes(byteArrayOf(1, 2, 3)),
            clientDataJson = Base64UrlBytes.fromBytes("{}".encodeToByteArray()),
            authenticatorData = Base64UrlBytes.fromBytes(authenticatorData),
            signature = Base64UrlBytes.fromBytes(byteArrayOf(9)),
        )

        val result = WebAuthnProtocolParser.parseAuthenticationResponse(raw)

        assertTrue(result is ValidationResult.Valid)
        assertEquals(raw.credentialId, result.value.credentialId)
        assertContentEquals(authenticatorData, result.value.rawAuthenticatorData.bytes())
    }

    private fun cborMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray {
        return cborHeader(5, entries.size) + entries.flatMap { (key, value) -> (key + value).asIterable() }.toByteArray()
    }

    private fun cborText(value: String): ByteArray = cborHeader(3, value.length) + value.encodeToByteArray()

    private fun cborBytes(value: ByteArray): ByteArray = cborHeader(2, value.size) + value

    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        return when {
            length < 24 -> byteArrayOf(((majorType shl 5) or length).toByte())
            length <= 0xFF -> byteArrayOf(((majorType shl 5) or 24).toByte(), length.toByte())
            else -> error("Test helper only supports one-byte CBOR lengths")
        }
    }
}
