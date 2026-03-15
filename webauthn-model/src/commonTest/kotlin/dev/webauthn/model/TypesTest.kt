package dev.webauthn.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TypesTest {
    @Test
    fun rpIdRequiresLowercaseHostLikeString() {
        val result = RpId.parse("Example.COM")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun rpIdRejectsInvalidDnsLabels() {
        assertTrue(RpId.parse("example..com") is ValidationResult.Invalid)
        assertTrue(RpId.parse("-example.com") is ValidationResult.Invalid)
        assertTrue(RpId.parse("example-.com") is ValidationResult.Invalid)
        assertTrue(RpId.parse("exa_mple.com") is ValidationResult.Invalid)
    }

    @Test
    fun rpIdRejectsTooLongLabel() {
        val tooLongLabel = "a".repeat(64)
        assertTrue(RpId.parse("$tooLongLabel.example") is ValidationResult.Invalid)
    }

    @Test
    fun rpIdAcceptsValidHostLabels() {
        val result = RpId.parse("login-1.example.com")
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun challengeRequiresAtLeast16Bytes() {
        val result = Challenge.parse("YWJj")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun originHasValueSemantics() {
        val first = Origin.parseOrThrow("https://example.com")
        val second = Origin.parseOrThrow("https://example.com")
        val third = Origin.parseOrThrow("https://login.example.com")

        assertEquals(first, second)
        assertFalse(first == third)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun challengeAndCredentialIdHaveValueSemantics() {
        val challengeA = Challenge.fromBytes(ByteArray(16) { 7 })
        val challengeB = Challenge.fromBytes(ByteArray(16) { 7 })
        val challengeC = Challenge.fromBytes(ByteArray(16) { 8 })
        assertEquals(challengeA, challengeB)
        assertFalse(challengeA == challengeC)

        val idA = CredentialId.fromBytes(ByteArray(16) { 3 })
        val idB = CredentialId.fromBytes(ByteArray(16) { 3 })
        val idC = CredentialId.fromBytes(ByteArray(16) { 4 })
        assertEquals(idA, idB)
        assertFalse(idA == idC)
    }

    @Test
    fun byteBackedNamedValuesRedactPayloadsInToString() {
        val challenge = Challenge.fromBytes(ByteArray(16) { 7 })
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 3 })
        val userHandle = UserHandle.fromBytes(ByteArray(32) { 5 })

        assertEquals("Challenge(16 bytes)", challenge.toString())
        assertEquals("CredentialId(16 bytes)", credentialId.toString())
        assertEquals("UserHandle(32 bytes)", userHandle.toString())
    }
}
