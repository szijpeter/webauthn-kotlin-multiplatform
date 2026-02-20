package dev.webauthn.server.ktor

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.getOrThrow
import dev.webauthn.server.AttestationPolicy
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.ChallengeStore
import dev.webauthn.server.CredentialStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.StoredCredential
import dev.webauthn.server.UserAccount
import dev.webauthn.server.UserAccountStore
import dev.webauthn.server.crypto.JvmRpIdHasher
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.testing.testApplication
import java.nio.file.Files
import java.sql.Connection
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals

class WebAuthnKtorRoutesH2StoreTest {

    @Test
    fun registrationAndAuthenticationStartRoutesWorkWithH2BackedStores() = testApplication {
        val adapter = H2KtorStoreAdapter.createTemporary()
        val challengeStore = adapter.challengeStore
        val credentialStore = adapter.credentialStore
        val userStore = adapter.userStore

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = JvmRpIdHasher(),
            attestationPolicy = AttestationPolicy.None,
        )

        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = JvmRpIdHasher(),
        )

        application {
            install(ContentNegotiation) { json() }
            installWebAuthnRoutes(registrationService, authenticationService)
        }

        val registrationStart = client.post("/webauthn/registration/start") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "rpId": "example.com",
                  "rpName": "Example",
                  "origin": "https://example.com",
                  "userName": "h2-user",
                  "userDisplayName": "H2 User",
                  "userHandle": "YWFhYWFhYWFhYWFhYWFhYQ"
                }
                """.trimIndent(),
            )
        }
        assertEquals(HttpStatusCode.OK, registrationStart.status)

        val authenticationStart = client.post("/webauthn/authentication/start") {
            contentType(ContentType.Application.Json)
            setBody(
                """
                {
                  "rpId": "example.com",
                  "origin": "https://example.com",
                  "userName": "h2-user"
                }
                """.trimIndent(),
            )
        }
        assertEquals(HttpStatusCode.OK, authenticationStart.status)

        adapter.close()
    }
}

private class H2KtorStoreAdapter private constructor(
    private val jdbcUrl: String,
    private val cleanup: () -> Unit,
) : AutoCloseable {
    val challengeStore: ChallengeStore = H2KtorChallengeStore(jdbcUrl)
    val credentialStore: CredentialStore = H2KtorCredentialStore(jdbcUrl)
    val userStore: UserAccountStore = H2KtorUserAccountStore(jdbcUrl)

    init {
        withConnection(jdbcUrl) { connection ->
            connection.createStatement().use { statement ->
                statement.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS challenge_sessions (
                        challenge_key VARCHAR PRIMARY KEY,
                        challenge_value VARCHAR NOT NULL,
                        ceremony_type VARCHAR NOT NULL,
                        rp_id VARCHAR NOT NULL,
                        origin_value VARCHAR NOT NULL,
                        user_name VARCHAR NOT NULL,
                        created_at_epoch_ms BIGINT NOT NULL,
                        expires_at_epoch_ms BIGINT NOT NULL
                    )
                    """.trimIndent(),
                )
                statement.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS credentials (
                        credential_id VARCHAR PRIMARY KEY,
                        user_id VARCHAR NOT NULL,
                        rp_id VARCHAR NOT NULL,
                        public_key VARBINARY NOT NULL,
                        sign_count BIGINT NOT NULL
                    )
                    """.trimIndent(),
                )
                statement.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS user_accounts (
                        user_name VARCHAR PRIMARY KEY,
                        user_id VARCHAR NOT NULL,
                        display_name VARCHAR NOT NULL
                    )
                    """.trimIndent(),
                )
            }
        }
    }

    override fun close() {
        cleanup()
    }

    companion object {
        fun createTemporary(prefix: String = "webauthn-ktor-h2-store"): H2KtorStoreAdapter {
            val tempDir = Files.createTempDirectory(prefix)
            val dbFile = tempDir.resolve("stores")
            val jdbcUrl = "jdbc:h2:file:${dbFile.toAbsolutePath()};DB_CLOSE_DELAY=-1;LOCK_MODE=3"
            return H2KtorStoreAdapter(jdbcUrl = jdbcUrl) {
                tempDir.toFile().deleteRecursively()
            }
        }
    }
}

private class H2KtorChallengeStore(
    private val jdbcUrl: String,
) : ChallengeStore {
    override suspend fun put(session: ChallengeSession) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                "MERGE INTO challenge_sessions KEY(challenge_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ).use { statement ->
                statement.setString(1, "${session.type.name}:${session.challenge.value.encoded()}")
                statement.setString(2, session.challenge.value.encoded())
                statement.setString(3, session.type.name)
                statement.setString(4, session.rpId.value)
                statement.setString(5, session.origin.value)
                statement.setString(6, session.userName)
                statement.setLong(7, session.createdAtEpochMs)
                statement.setLong(8, session.expiresAtEpochMs)
                statement.executeUpdate()
            }
        }
    }

    override suspend fun consume(challenge: Challenge, type: CeremonyType): ChallengeSession? {
        return withConnection(jdbcUrl) { connection ->
            connection.autoCommit = false
            connection.transactionIsolation = Connection.TRANSACTION_SERIALIZABLE
            try {
                val key = "${type.name}:${challenge.value.encoded()}"
                val session = connection.prepareStatement(
                    """
                    SELECT challenge_value, ceremony_type, rp_id, origin_value, user_name, created_at_epoch_ms, expires_at_epoch_ms
                    FROM challenge_sessions
                    WHERE challenge_key = ?
                    FOR UPDATE
                    """.trimIndent(),
                ).use { select ->
                    select.setString(1, key)
                    select.executeQuery().use { resultSet ->
                        if (!resultSet.next()) {
                            null
                        } else {
                            ChallengeSession(
                                challenge = Challenge.parseOrThrow(resultSet.getString("challenge_value")),
                                rpId = RpId.parseOrThrow(resultSet.getString("rp_id")),
                                origin = Origin.parseOrThrow(resultSet.getString("origin_value")),
                                userName = resultSet.getString("user_name"),
                                createdAtEpochMs = resultSet.getLong("created_at_epoch_ms"),
                                expiresAtEpochMs = resultSet.getLong("expires_at_epoch_ms"),
                                type = CeremonyType.valueOf(resultSet.getString("ceremony_type")),
                            )
                        }
                    }
                }
                if (session != null) {
                    connection.prepareStatement("DELETE FROM challenge_sessions WHERE challenge_key = ?").use { delete ->
                        delete.setString(1, key)
                        delete.executeUpdate()
                    }
                }
                connection.commit()
                session
            } catch (t: Throwable) {
                connection.rollback()
                throw t
            }
        }
    }
}

private class H2KtorCredentialStore(
    private val jdbcUrl: String,
) : CredentialStore {
    override suspend fun save(credential: StoredCredential) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                "MERGE INTO credentials KEY(credential_id) VALUES (?, ?, ?, ?, ?)",
            ).use { statement ->
                statement.setString(1, credential.credentialId.value.encoded())
                statement.setString(2, credential.userId.value.encoded())
                statement.setString(3, credential.rpId.value)
                statement.setBytes(4, credential.publicKeyCose)
                statement.setLong(5, credential.signCount)
                statement.executeUpdate()
            }
        }
    }

    override suspend fun findById(id: CredentialId): StoredCredential? {
        return withConnection(jdbcUrl) { connection ->
            connection.prepareStatement("SELECT credential_id, user_id, rp_id, public_key, sign_count FROM credentials WHERE credential_id = ?").use { statement ->
                statement.setString(1, id.value.encoded())
                statement.executeQuery().use { resultSet ->
                    if (!resultSet.next()) {
                        null
                    } else {
                        StoredCredential(
                            credentialId = CredentialId.parseOrThrow(resultSet.getString("credential_id")),
                            userId = UserHandle.parse(resultSet.getString("user_id")).getOrThrow(),
                            rpId = RpId.parseOrThrow(resultSet.getString("rp_id")),
                            publicKeyCose = resultSet.getBytes("public_key"),
                            signCount = resultSet.getLong("sign_count"),
                        )
                    }
                }
            }
        }
    }

    override suspend fun findByUserId(userId: UserHandle): List<StoredCredential> {
        return withConnection(jdbcUrl) { connection ->
            connection.prepareStatement("SELECT credential_id, user_id, rp_id, public_key, sign_count FROM credentials WHERE user_id = ?").use { statement ->
                statement.setString(1, userId.value.encoded())
                statement.executeQuery().use { resultSet ->
                    val items = mutableListOf<StoredCredential>()
                    while (resultSet.next()) {
                        items += StoredCredential(
                            credentialId = CredentialId.parseOrThrow(resultSet.getString("credential_id")),
                            userId = UserHandle.parse(resultSet.getString("user_id")).getOrThrow(),
                            rpId = RpId.parseOrThrow(resultSet.getString("rp_id")),
                            publicKeyCose = resultSet.getBytes("public_key"),
                            signCount = resultSet.getLong("sign_count"),
                        )
                    }
                    items
                }
            }
        }
    }

    override suspend fun updateSignCount(id: CredentialId, signCount: Long) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement("UPDATE credentials SET sign_count = ? WHERE credential_id = ?").use { statement ->
                statement.setLong(1, signCount)
                statement.setString(2, id.value.encoded())
                statement.executeUpdate()
            }
        }
    }
}

private class H2KtorUserAccountStore(
    private val jdbcUrl: String,
) : UserAccountStore {
    override suspend fun findByName(name: String): UserAccount? {
        return withConnection(jdbcUrl) { connection ->
            connection.prepareStatement("SELECT user_name, user_id, display_name FROM user_accounts WHERE user_name = ?").use { statement ->
                statement.setString(1, name)
                statement.executeQuery().use { resultSet ->
                    if (!resultSet.next()) {
                        null
                    } else {
                        UserAccount(
                            id = UserHandle.parse(resultSet.getString("user_id")).getOrThrow(),
                            name = resultSet.getString("user_name"),
                            displayName = resultSet.getString("display_name"),
                        )
                    }
                }
            }
        }
    }

    override suspend fun save(user: UserAccount) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                "MERGE INTO user_accounts KEY(user_name) VALUES (?, ?, ?)",
            ).use { statement ->
                statement.setString(1, user.name)
                statement.setString(2, user.id.value.encoded())
                statement.setString(3, user.displayName)
                statement.executeUpdate()
            }
        }
    }
}

private inline fun <T> withConnection(jdbcUrl: String, block: (Connection) -> T): T {
    DriverManager.getConnection(jdbcUrl).use { connection ->
        return block(connection)
    }
}
