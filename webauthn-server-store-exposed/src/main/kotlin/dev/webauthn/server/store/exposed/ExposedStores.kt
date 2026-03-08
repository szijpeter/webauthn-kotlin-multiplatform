package dev.webauthn.server.store.exposed

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.getOrThrow
import dev.webauthn.server.ChallengeStore
import dev.webauthn.server.CredentialStore
import dev.webauthn.server.StoredCredential
import dev.webauthn.server.UserAccount
import dev.webauthn.server.UserAccountStore
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.Column
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import org.jetbrains.exposed.v1.jdbc.SchemaUtils
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.exists
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.jetbrains.exposed.v1.migration.jdbc.MigrationUtils

public object ChallengeSessions : Table("challenge_sessions") {
    public val challengeKey: Column<String> = varchar("challenge_key", 255)
    public val challengeValue: Column<String> = varchar("challenge_value", 255)
    public val ceremonyType: Column<String> = varchar("ceremony_type", 50)
    public val rpId: Column<String> = varchar("rp_id", 255)
    public val originValue: Column<String> = varchar("origin_value", 1024)
    public val userName: Column<String> = varchar("user_name", 255)
    public val createdAtEpochMs: Column<Long> = long("created_at_epoch_ms")
    public val expiresAtEpochMs: Column<Long> = long("expires_at_epoch_ms")
    public val userVerification: Column<String?> = varchar("user_verification", 50).nullable()
    public val extensions: Column<String?> = varchar("extensions", 4096).nullable()

    override val primaryKey: PrimaryKey = PrimaryKey(challengeKey)
}

public object Credentials : Table("credentials") {
    public val credentialId: Column<String> = varchar("credential_id", 255)
    public val userId: Column<String> = varchar("user_id", 255)
    public val rpId: Column<String> = varchar("rp_id", 255)
    public val publicKey: Column<ByteArray> = binary("public_key")
    public val signCount: Column<Long> = long("sign_count")

    override val primaryKey: PrimaryKey = PrimaryKey(credentialId)
}

public object UserAccounts : Table("user_accounts") {
    public val userName: Column<String> = varchar("user_name", 255)
    public val userId: Column<String> = varchar("user_id", 255)
    public val displayName: Column<String> = varchar("display_name", 255)

    override val primaryKey: PrimaryKey = PrimaryKey(userName)
}

private val WEB_AUTHN_SCHEMA_TABLES: Array<Table> = arrayOf(ChallengeSessions, Credentials, UserAccounts)

public fun initializeWebAuthnSchema(database: Database) {
    transaction(database) {
        val existingTables = WEB_AUTHN_SCHEMA_TABLES.filter { it.exists() }
        if (existingTables.isEmpty()) {
            SchemaUtils.create(*WEB_AUTHN_SCHEMA_TABLES)
            return@transaction
        }

        validateCurrentWebAuthnSchema(existingTables)
    }
}

public fun webAuthnSchemaMigrationStatements(database: Database): List<String> =
    transaction(database) {
        currentWebAuthnSchemaMigrationStatements()
    }

public fun validateWebAuthnSchema(database: Database) {
    transaction(database) {
        validateCurrentWebAuthnSchema(WEB_AUTHN_SCHEMA_TABLES.filter { it.exists() })
    }
}

private fun currentWebAuthnSchemaMigrationStatements(): List<String> =
    MigrationUtils.statementsRequiredForDatabaseMigration(*WEB_AUTHN_SCHEMA_TABLES)

private fun validateCurrentWebAuthnSchema(existingTables: List<Table>) {
    val migrationStatements = currentWebAuthnSchemaMigrationStatements()
    check(migrationStatements.isEmpty()) {
        buildString {
            appendLine("WebAuthn Exposed schema drift detected.")
            if (existingTables.isEmpty()) {
                appendLine("Detected an uninitialized schema.")
            } else if (existingTables.size != WEB_AUTHN_SCHEMA_TABLES.size) {
                appendLine(
                    "Detected a partially initialized schema with existing tables: " +
                        existingTables.joinToString { it.tableName }
                )
            }
            appendLine("Apply the following migration statements with your migration tool:")
            migrationStatements.forEach(::appendLine)
        }.trimEnd()
    }
}

private suspend fun <T> Database.ioTransaction(statement: suspend JdbcTransaction.() -> T): T =
    withContext(Dispatchers.IO) {
        suspendTransaction(db = this@ioTransaction, statement = statement)
    }

public class ExposedChallengeStore(private val db: Database) : ChallengeStore {
    override suspend fun put(session: ChallengeSession) {
        db.ioTransaction {
            val key = key(session.challenge, session.type)
            val exists = ChallengeSessions.selectAll().where { ChallengeSessions.challengeKey eq key }.singleOrNull() != null
            if (exists) {
                ChallengeSessions.update({ ChallengeSessions.challengeKey eq key }) {
                    it[challengeValue] = session.challenge.value.encoded()
                    it[ceremonyType] = session.type.name
                    it[rpId] = session.rpId.value
                    it[originValue] = session.origin.value
                    it[userName] = session.userName
                    it[createdAtEpochMs] = session.createdAtEpochMs
                    it[expiresAtEpochMs] = session.expiresAtEpochMs
                    it[userVerification] = session.userVerification?.name
                    it[extensions] = session.extensions?.let { ext -> Json.encodeToString(WebAuthnDtoMapper.fromModel(ext)) }
                }
            } else {
                ChallengeSessions.insert {
                    it[challengeKey] = key
                    it[challengeValue] = session.challenge.value.encoded()
                    it[ceremonyType] = session.type.name
                    it[rpId] = session.rpId.value
                    it[originValue] = session.origin.value
                    it[userName] = session.userName
                    it[createdAtEpochMs] = session.createdAtEpochMs
                    it[expiresAtEpochMs] = session.expiresAtEpochMs
                    it[userVerification] = session.userVerification?.name
                    it[extensions] = session.extensions?.let { ext -> Json.encodeToString(WebAuthnDtoMapper.fromModel(ext)) }
                }
            }
        }
    }

    override suspend fun consume(challenge: Challenge, type: CeremonyType): ChallengeSession? {
        return db.ioTransaction {
            val key = key(challenge, type)
            val row = ChallengeSessions.selectAll().where { ChallengeSessions.challengeKey eq key }
                .forUpdate()
                .singleOrNull() ?: return@ioTransaction null
            
            val session = ChallengeSession(
                challenge = Challenge.parseOrThrow(row[ChallengeSessions.challengeValue]),
                rpId = RpId.parseOrThrow(row[ChallengeSessions.rpId]),
                origin = Origin.parseOrThrow(row[ChallengeSessions.originValue]),
                userName = row[ChallengeSessions.userName],
                createdAtEpochMs = row[ChallengeSessions.createdAtEpochMs],
                expiresAtEpochMs = row[ChallengeSessions.expiresAtEpochMs],
                type = CeremonyType.valueOf(row[ChallengeSessions.ceremonyType]),
                userVerification = row[ChallengeSessions.userVerification]?.let { dev.webauthn.model.UserVerificationRequirement.valueOf(it) },
                extensions = row[ChallengeSessions.extensions]?.let { json ->
                    val dto = Json.decodeFromString<AuthenticationExtensionsClientInputsDto>(json)
                    when (val res = WebAuthnDtoMapper.toModelValidated(dto)) {
                        is dev.webauthn.model.ValidationResult.Valid -> res.value
                        is dev.webauthn.model.ValidationResult.Invalid -> null
                    }
                },
            )
            
            ChallengeSessions.deleteWhere { challengeKey eq key }
            
            session
        }
    }

    private fun key(challenge: Challenge, type: CeremonyType): String {
        return "${type.name}:${challenge.value.encoded()}"
    }
}

public class ExposedCredentialStore(private val db: Database) : CredentialStore {
    override suspend fun save(credential: StoredCredential) {
        db.ioTransaction {
            val exists = Credentials.selectAll().where { Credentials.credentialId eq credential.credentialId.value.encoded() }.singleOrNull() != null
            if (exists) {
                Credentials.update({ Credentials.credentialId eq credential.credentialId.value.encoded() }) {
                    it[userId] = credential.userId.value.encoded()
                    it[rpId] = credential.rpId.value
                    it[publicKey] = credential.publicKeyCose.bytes()
                    it[signCount] = credential.signCount
                }
            } else {
                Credentials.insert {
                    it[credentialId] = credential.credentialId.value.encoded()
                    it[userId] = credential.userId.value.encoded()
                    it[rpId] = credential.rpId.value
                    it[publicKey] = credential.publicKeyCose.bytes()
                    it[signCount] = credential.signCount
                }
            }
        }
    }

    override suspend fun findById(id: CredentialId): StoredCredential? {
        return db.ioTransaction {
            Credentials.selectAll().where { Credentials.credentialId eq id.value.encoded() }
                .singleOrNull()?.let { row ->
                    StoredCredential(
                        credentialId = CredentialId.parseOrThrow(row[Credentials.credentialId]),
                        userId = UserHandle.parse(row[Credentials.userId]).getOrThrow(),
                        rpId = RpId.parseOrThrow(row[Credentials.rpId]),
                        publicKeyCose = dev.webauthn.model.CosePublicKey.fromBytes(row[Credentials.publicKey]),
                        signCount = row[Credentials.signCount],
                    )
                }
        }
    }

    override suspend fun findByUserId(userId: UserHandle): List<StoredCredential> {
        return db.ioTransaction {
            Credentials.selectAll().where { Credentials.userId eq userId.value.encoded() }
                .map { row ->
                    StoredCredential(
                        credentialId = CredentialId.parseOrThrow(row[Credentials.credentialId]),
                        userId = UserHandle.parse(row[Credentials.userId]).getOrThrow(),
                        rpId = RpId.parseOrThrow(row[Credentials.rpId]),
                        publicKeyCose = dev.webauthn.model.CosePublicKey.fromBytes(row[Credentials.publicKey]),
                        signCount = row[Credentials.signCount],
                    )
                }
        }
    }

    override suspend fun updateSignCount(id: CredentialId, signCount: Long) {
        db.ioTransaction {
            Credentials.update({ Credentials.credentialId eq id.value.encoded() }) {
                it[Credentials.signCount] = signCount
            }
        }
    }
}

public class ExposedUserAccountStore(private val db: Database) : UserAccountStore {
    override suspend fun findByName(name: String): UserAccount? {
        return db.ioTransaction {
            UserAccounts.selectAll().where { UserAccounts.userName eq name }
                .singleOrNull()?.let { row ->
                    UserAccount(
                        id = UserHandle.parse(row[UserAccounts.userId]).getOrThrow(),
                        name = row[UserAccounts.userName],
                        displayName = row[UserAccounts.displayName],
                    )
                }
        }
    }

    override suspend fun save(user: UserAccount) {
        db.ioTransaction {
            val exists = UserAccounts.selectAll().where { UserAccounts.userName eq user.name }.singleOrNull() != null
            if (exists) {
                UserAccounts.update({ UserAccounts.userName eq user.name }) {
                    it[userId] = user.id.value.encoded()
                    it[displayName] = user.displayName
                }
            } else {
                UserAccounts.insert {
                    it[userName] = user.name
                    it[userId] = user.id.value.encoded()
                    it[displayName] = user.displayName
                }
            }
        }
    }
}
