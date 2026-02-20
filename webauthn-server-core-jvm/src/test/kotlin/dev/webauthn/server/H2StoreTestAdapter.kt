package dev.webauthn.server

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.getOrThrow
import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager

internal class H2StoreTestAdapter private constructor(
    private val jdbcUrl: String,
    private val cleanup: () -> Unit,
) : AutoCloseable {

    val challengeStore: ChallengeStore = H2ChallengeStore(jdbcUrl)
    val credentialStore: CredentialStore = H2CredentialStore(jdbcUrl)
    val userStore: UserAccountStore = H2UserAccountStore(jdbcUrl)

    init {
        initializeSchema()
    }

    override fun close() {
        cleanup()
    }

    companion object {
        fun createTemporary(prefix: String = "webauthn-h2-store-contract"): H2StoreTestAdapter {
            val tempDir = Files.createTempDirectory(prefix)
            return create(dbFile = tempDir.resolve("stores")) {
                tempDir.toFile().deleteRecursively()
            }
        }

        fun createPersistent(dbFile: Path): H2StoreTestAdapter = create(dbFile = dbFile)

        private fun create(dbFile: Path, cleanup: () -> Unit = {}): H2StoreTestAdapter {
            Files.createDirectories(dbFile.parent)
            val jdbcUrl = "jdbc:h2:file:${dbFile.toAbsolutePath()};DB_CLOSE_DELAY=-1;LOCK_MODE=3"
            return H2StoreTestAdapter(jdbcUrl = jdbcUrl, cleanup = cleanup)
        }
    }

    private fun initializeSchema() {
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
}

private class H2ChallengeStore(
    private val jdbcUrl: String,
) : ChallengeStore {
    override suspend fun put(session: ChallengeSession) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                """
                MERGE INTO challenge_sessions KEY(challenge_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
            ).use { statement ->
                statement.setString(1, key(session.challenge, session.type))
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
                val session = connection.prepareStatement(
                    """
                    SELECT challenge_value, ceremony_type, rp_id, origin_value, user_name, created_at_epoch_ms, expires_at_epoch_ms
                    FROM challenge_sessions
                    WHERE challenge_key = ?
                    FOR UPDATE
                    """.trimIndent(),
                ).use { select ->
                    select.setString(1, key(challenge, type))
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
                        delete.setString(1, key(challenge, type))
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

    private fun key(challenge: Challenge, type: CeremonyType): String {
        return "${type.name}:${challenge.value.encoded()}"
    }
}

private class H2CredentialStore(
    private val jdbcUrl: String,
) : CredentialStore {
    override suspend fun save(credential: StoredCredential) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                """
                MERGE INTO credentials KEY(credential_id)
                VALUES (?, ?, ?, ?, ?)
                """.trimIndent(),
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
            connection.prepareStatement(
                "SELECT credential_id, user_id, rp_id, public_key, sign_count FROM credentials WHERE credential_id = ?",
            ).use { statement ->
                statement.setString(1, id.value.encoded())
                statement.executeQuery().use { resultSet ->
                    if (!resultSet.next()) {
                        null
                    } else {
                        resultSet.toStoredCredential()
                    }
                }
            }
        }
    }

    override suspend fun findByUserId(userId: UserHandle): List<StoredCredential> {
        return withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                "SELECT credential_id, user_id, rp_id, public_key, sign_count FROM credentials WHERE user_id = ? ORDER BY credential_id",
            ).use { statement ->
                statement.setString(1, userId.value.encoded())
                statement.executeQuery().use { resultSet ->
                    val credentials = mutableListOf<StoredCredential>()
                    while (resultSet.next()) {
                        credentials += resultSet.toStoredCredential()
                    }
                    credentials
                }
            }
        }
    }

    override suspend fun updateSignCount(id: CredentialId, signCount: Long) {
        withConnection(jdbcUrl) { connection ->
            connection.prepareStatement(
                "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            ).use { statement ->
                statement.setLong(1, signCount)
                statement.setString(2, id.value.encoded())
                statement.executeUpdate()
            }
        }
    }
}

private class H2UserAccountStore(
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
                """
                MERGE INTO user_accounts KEY(user_name)
                VALUES (?, ?, ?)
                """.trimIndent(),
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

private fun java.sql.ResultSet.toStoredCredential(): StoredCredential {
    return StoredCredential(
        credentialId = CredentialId.parseOrThrow(getString("credential_id")),
        userId = UserHandle.parse(getString("user_id")).getOrThrow(),
        rpId = RpId.parseOrThrow(getString("rp_id")),
        publicKeyCose = getBytes("public_key"),
        signCount = getLong("sign_count"),
    )
}
