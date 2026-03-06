package dev.webauthn.server.store.exposed

import dev.webauthn.server.StoreContractTestBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import java.nio.file.Files

class ExposedStoresH2Test : StoreContractTestBase() {
    override fun createStoreFixture(): StoreFixture {
        val tempDir = Files.createTempDirectory("webauthn-exposed-h2")
        val dbFile = tempDir.resolve("test")
        val database = Database.connect(
            url = "jdbc:h2:file:${dbFile.toAbsolutePath()};DB_CLOSE_DELAY=-1",
            driver = "org.h2.Driver",
        )
        initializeWebAuthnSchema(database)
        return StoreFixture(
            challengeStore = ExposedChallengeStore(database),
            credentialStore = ExposedCredentialStore(database),
            userStore = ExposedUserAccountStore(database),
            cleanup = {
                transaction(database) {
                    ChallengeSessions.deleteAll()
                    Credentials.deleteAll()
                    UserAccounts.deleteAll()
                }
                tempDir.toFile().deleteRecursively()
            },
        )
    }
}
