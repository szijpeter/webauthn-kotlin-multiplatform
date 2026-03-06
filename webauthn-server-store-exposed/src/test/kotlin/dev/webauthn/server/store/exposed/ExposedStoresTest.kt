package dev.webauthn.server.store.exposed

import dev.webauthn.server.StoreContractTestBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.condition.EnabledIf
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName

@EnabledIf("isDockerAvailable")
class ExposedStoresTest : StoreContractTestBase() {
    companion object {
        @JvmStatic
        private val postgres = PostgreSQLContainer(DockerImageName.parse("postgres:15-alpine"))

        @JvmStatic
        private lateinit var database: Database

        @JvmStatic
        fun isDockerAvailable(): Boolean = try {
            DockerClientFactory.instance().isDockerAvailable
        } catch (_: Exception) {
            false
        }

        @JvmStatic
        @BeforeAll
        fun setupPostgres() {
            postgres.start()
            database = Database.connect(
                url = postgres.jdbcUrl,
                user = postgres.username,
                password = postgres.password,
                driver = postgres.driverClassName,
            )
            initializeWebAuthnSchema(database)
        }

        @JvmStatic
        @AfterAll
        fun teardownPostgres() {
            if (postgres.isRunning) {
                postgres.stop()
            }
        }
    }

    override fun createStoreFixture(): StoreFixture {
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
            },
        )
    }
}
