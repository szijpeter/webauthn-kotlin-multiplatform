package dev.webauthn.server

import dev.webauthn.model.CredentialId
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

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
}
