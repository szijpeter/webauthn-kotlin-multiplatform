package dev.webauthn.server

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class InMemoryStoresTest {
    @Test
    fun credentialStoreUpdatesSignCount() = runBlocking {
        val store = InMemoryCredentialStore()
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 3 })
        val userHandle = UserHandle.fromBytes(ByteArray(16) { 2 })

        store.save(
            StoredCredential(
                credentialId = credentialId,
                userId = userHandle,
                rpId = RpId.parseOrThrow("example.com"),
                publicKeyCose = byteArrayOf(1, 2, 3),
                signCount = 1,
            ),
        )
        store.updateSignCount(credentialId, 42)

        assertEquals(42, store.findById(credentialId)?.signCount)
    }

    @Test
    fun challengeStoreConsumeIsAtomicDoubleConsumeReturnsNull() = runBlocking {
        val store = InMemoryChallengeStore()
        val challenge = Challenge.fromBytes(ByteArray(32) { 0x01 })

        store.put(
            ChallengeSession(
                challenge = challenge,
                rpId = RpId.parseOrThrow("example.com"),
                origin = dev.webauthn.model.Origin.parseOrThrow("https://example.com"),
                userName = "alice",
                createdAtEpochMs = 1000L,
                expiresAtEpochMs = 61_000L,
                type = CeremonyType.REGISTRATION,
            ),
        )

        val first = store.consume(challenge, CeremonyType.REGISTRATION)
        assertNotNull(first)

        val second = store.consume(challenge, CeremonyType.REGISTRATION)
        assertNull(second, "Second consume of same challenge must return null")
    }

    @Test
    fun credentialStoreSaveOverwritesExistingCleanly() = runBlocking {
        val store = InMemoryCredentialStore()
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 3 })
        val userHandle = UserHandle.fromBytes(ByteArray(16) { 2 })
        val rpId = RpId.parseOrThrow("example.com")

        store.save(
            StoredCredential(
                credentialId = credentialId,
                userId = userHandle,
                rpId = rpId,
                publicKeyCose = byteArrayOf(1, 2, 3),
                signCount = 1,
            ),
        )

        // Overwrite with different sign count
        store.save(
            StoredCredential(
                credentialId = credentialId,
                userId = userHandle,
                rpId = rpId,
                publicKeyCose = byteArrayOf(4, 5, 6),
                signCount = 99,
            ),
        )

        val found = store.findById(credentialId)
        assertNotNull(found)
        assertEquals(99, found.signCount)
        assertEquals(1, store.findByUserId(userHandle).size, "Overwrite should not create duplicate entries")
    }

    @Test
    fun credentialStoreFindByUserIdReflectsUpdatedSignCount() = runBlocking {
        val store = InMemoryCredentialStore()
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 3 })
        val userHandle = UserHandle.fromBytes(ByteArray(16) { 2 })

        store.save(
            StoredCredential(
                credentialId = credentialId,
                userId = userHandle,
                rpId = RpId.parseOrThrow("example.com"),
                publicKeyCose = byteArrayOf(1, 2, 3),
                signCount = 1,
            ),
        )

        store.updateSignCount(credentialId, 77)

        val byUser = store.findByUserId(userHandle)
        assertEquals(1, byUser.size)
        assertEquals(77, byUser[0].signCount)
    }
}
