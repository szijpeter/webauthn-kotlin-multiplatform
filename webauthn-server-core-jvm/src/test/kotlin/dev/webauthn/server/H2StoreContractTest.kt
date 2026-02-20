package dev.webauthn.server

import dev.webauthn.model.CredentialId
import dev.webauthn.model.UserHandle
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals

class H2StoreContractTest : StoreContractTestBase() {
    override fun createStoreFixture(): StoreFixture {
        val adapter = H2StoreTestAdapter.createTemporary()
        return StoreFixture(
            challengeStore = adapter.challengeStore,
            credentialStore = adapter.credentialStore,
            userStore = adapter.userStore,
            cleanup = adapter::close,
        )
    }

    @Test
    fun signCountUpdatePersistsAcrossStoreReinstantiation() = runBlocking {
        val tempDir = Files.createTempDirectory("webauthn-h2-sign-count")
        val dbFile = tempDir.resolve("stores")
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x2A })
        val userHandle = UserHandle.fromBytes(ByteArray(16) { 0x3B })

        val first = H2StoreTestAdapter.createPersistent(dbFile)
        try {
            first.userStore.save(UserAccount(userHandle, "persistent", "Persistent User"))
            first.credentialStore.save(StoredCredential(credentialId, userHandle, rpId, byteArrayOf(1, 2, 3), 1))
            first.credentialStore.updateSignCount(credentialId, 9)
        } finally {
            first.close()
        }

        val second = H2StoreTestAdapter.createPersistent(dbFile)
        try {
            val stored = second.credentialStore.findById(credentialId)
            assertEquals(9, stored?.signCount)
        } finally {
            second.close()
            tempDir.toFile().deleteRecursively()
        }
    }
}
