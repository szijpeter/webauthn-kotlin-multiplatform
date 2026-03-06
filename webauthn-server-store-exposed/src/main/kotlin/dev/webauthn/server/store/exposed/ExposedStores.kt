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
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update

public object ChallengeSessions : Table("challenge_sessions") {
    public val challengeKey: org.jetbrains.exposed.sql.Column<String> = varchar("challenge_key", 255)
    public val challengeValue: org.jetbrains.exposed.sql.Column<String> = varchar("challenge_value", 255)
    public val ceremonyType: org.jetbrains.exposed.sql.Column<String> = varchar("ceremony_type", 50)
    public val rpId: org.jetbrains.exposed.sql.Column<String> = varchar("rp_id", 255)
    public val originValue: org.jetbrains.exposed.sql.Column<String> = varchar("origin_value", 1024)
    public val userName: org.jetbrains.exposed.sql.Column<String> = varchar("user_name", 255)
    public val createdAtEpochMs: org.jetbrains.exposed.sql.Column<Long> = long("created_at_epoch_ms")
    public val expiresAtEpochMs: org.jetbrains.exposed.sql.Column<Long> = long("expires_at_epoch_ms")
    public val userVerification: org.jetbrains.exposed.sql.Column<String?> = varchar("user_verification", 50).nullable()
    public val extensions: org.jetbrains.exposed.sql.Column<String?> = varchar("extensions", 4096).nullable()

    override val primaryKey: PrimaryKey = PrimaryKey(challengeKey)
}

public object Credentials : Table("credentials") {
    public val credentialId: org.jetbrains.exposed.sql.Column<String> = varchar("credential_id", 255)
    public val userId: org.jetbrains.exposed.sql.Column<String> = varchar("user_id", 255)
    public val rpId: org.jetbrains.exposed.sql.Column<String> = varchar("rp_id", 255)
    public val publicKey: org.jetbrains.exposed.sql.Column<ByteArray> = binary("public_key")
    public val signCount: org.jetbrains.exposed.sql.Column<Long> = long("sign_count")

    override val primaryKey: PrimaryKey = PrimaryKey(credentialId)
}

public object UserAccounts : Table("user_accounts") {
    public val userName: org.jetbrains.exposed.sql.Column<String> = varchar("user_name", 255)
    public val userId: org.jetbrains.exposed.sql.Column<String> = varchar("user_id", 255)
    public val displayName: org.jetbrains.exposed.sql.Column<String> = varchar("display_name", 255)

    override val primaryKey: PrimaryKey = PrimaryKey(userName)
}

public fun initializeWebAuthnSchema(database: Database) {
    transaction(database) {
        SchemaUtils.createMissingTablesAndColumns(ChallengeSessions, Credentials, UserAccounts)
    }
}

public class ExposedChallengeStore(private val db: Database) : ChallengeStore {
    override suspend fun put(session: ChallengeSession) {
        newSuspendedTransaction(Dispatchers.IO, db) {
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
        return newSuspendedTransaction<ChallengeSession?>(Dispatchers.IO, db) {
            val key = key(challenge, type)
            val row = ChallengeSessions.selectAll().where { ChallengeSessions.challengeKey eq key }
                .forUpdate()
                .singleOrNull() ?: return@newSuspendedTransaction null
            
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
        newSuspendedTransaction(Dispatchers.IO, db) {
            val exists = Credentials.selectAll().where { Credentials.credentialId eq credential.credentialId.value.encoded() }.singleOrNull() != null
            if (exists) {
                Credentials.update({ Credentials.credentialId eq credential.credentialId.value.encoded() }) {
                    it[userId] = credential.userId.value.encoded()
                    it[rpId] = credential.rpId.value
                    it[publicKey] = credential.publicKeyCose
                    it[signCount] = credential.signCount
                }
            } else {
                Credentials.insert {
                    it[credentialId] = credential.credentialId.value.encoded()
                    it[userId] = credential.userId.value.encoded()
                    it[rpId] = credential.rpId.value
                    it[publicKey] = credential.publicKeyCose
                    it[signCount] = credential.signCount
                }
            }
        }
    }

    override suspend fun findById(id: CredentialId): StoredCredential? {
        return newSuspendedTransaction<StoredCredential?>(Dispatchers.IO, db) {
            Credentials.selectAll().where { Credentials.credentialId eq id.value.encoded() }
                .singleOrNull()?.let { row ->
                    StoredCredential(
                        credentialId = CredentialId.parseOrThrow(row[Credentials.credentialId]),
                        userId = UserHandle.parse(row[Credentials.userId]).getOrThrow(),
                        rpId = RpId.parseOrThrow(row[Credentials.rpId]),
                        publicKeyCose = row[Credentials.publicKey],
                        signCount = row[Credentials.signCount],
                    )
                }
        }
    }

    override suspend fun findByUserId(userId: UserHandle): List<StoredCredential> {
        return newSuspendedTransaction<List<StoredCredential>>(Dispatchers.IO, db) {
            Credentials.selectAll().where { Credentials.userId eq userId.value.encoded() }
                .map { row ->
                    StoredCredential(
                        credentialId = CredentialId.parseOrThrow(row[Credentials.credentialId]),
                        userId = UserHandle.parse(row[Credentials.userId]).getOrThrow(),
                        rpId = RpId.parseOrThrow(row[Credentials.rpId]),
                        publicKeyCose = row[Credentials.publicKey],
                        signCount = row[Credentials.signCount],
                    )
                }
        }
    }

    override suspend fun updateSignCount(id: CredentialId, signCount: Long) {
        newSuspendedTransaction(Dispatchers.IO, db) {
            Credentials.update({ Credentials.credentialId eq id.value.encoded() }) {
                it[Credentials.signCount] = signCount
            }
        }
    }
}

public class ExposedUserAccountStore(private val db: Database) : UserAccountStore {
    override suspend fun findByName(name: String): UserAccount? {
        return newSuspendedTransaction<UserAccount?>(Dispatchers.IO, db) {
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
        newSuspendedTransaction(Dispatchers.IO, db) {
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
