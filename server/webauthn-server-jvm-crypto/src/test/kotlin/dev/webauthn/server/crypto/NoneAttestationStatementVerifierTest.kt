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
import kotlin.test.Test
import kotlin.test.assertTrue

class NoneAttestationStatementVerifierTest {
    private val verifier = NoneAttestationStatementVerifier()

    @Test
    fun verifyPassesForNoneFmtWithEmptyAttStmt() {
        val attestationObject = attestationObjectCbor(fmt = "none", attStmtEntries = emptyList())
        val input = sampleInput(attestationObject)

        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun verifyFailsForNoneFmtWithNonEmptyAttStmt() {
        val attestationObject = attestationObjectCbor(
            fmt = "none",
            attStmtEntries = listOf("sig" to cborBytes(byteArrayOf(1, 2, 3))),
        )
        val input = sampleInput(attestationObject)

        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun verifyFailsForUnsupportedFmt() {
        val attestationObject = attestationObjectCbor(fmt = "packed", attStmtEntries = emptyList())
        val input = sampleInput(attestationObject)

        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun verifyFailsForEmptyAttestationObject() {
        val input = sampleInput(byteArrayOf())

        val result = verifier.verify(input)

        assertTrue(result is ValidationResult.Invalid)
    }

    private fun sampleInput(attestationObject: ByteArray): RegistrationValidationInput {
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x11 })
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
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                attestationObject = Base64UrlBytes.fromBytes(attestationObject),
                rawAuthenticatorData = AuthenticatorData(
                    rpIdHash = rpIdHash(),
                    flags = 0x41,
                    signCount = 0,
                ),
                attestedCredentialData = AttestedCredentialData(
                    aaguid = aaguid(),
                    credentialId = credentialId,
                    cosePublicKey = cosePublicKey(0xA1, 0x01, 0x02),
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

    private fun attestationObjectCbor(
        fmt: String,
        attStmtEntries: List<Pair<String, ByteArray>>,
    ): ByteArray {
        val authData = ByteArray(37) { if (it < 32) 0x10 else 0x00 }
        authData[32] = 0x01 // UP flag
        return cborMap(
            "fmt" to cborText(fmt),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(*attStmtEntries.toTypedArray()),
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
        return if (length < 24) {
            byteArrayOf(((majorType shl 5) or length).toByte())
        } else {
            byteArrayOf(((majorType shl 5) or 24).toByte(), length.toByte())
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
}
