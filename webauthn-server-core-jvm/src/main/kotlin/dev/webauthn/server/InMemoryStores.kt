package dev.webauthn.server

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.UserHandle
import java.util.concurrent.ConcurrentHashMap

public class InMemoryChallengeStore : ChallengeStore {
    private val sessions: MutableMap<String, ChallengeSession> = ConcurrentHashMap()

    override suspend fun put(session: ChallengeSession) {
        sessions[key(session.challenge, session.type)] = session
    }

    override suspend fun consume(challenge: Challenge, type: CeremonyType): ChallengeSession? {
        return sessions.remove(key(challenge, type))
    }

    private fun key(challenge: Challenge, type: CeremonyType): String {
        return "${type.name}:${challenge.value.encoded()}"
    }
}

public class InMemoryCredentialStore : CredentialStore {
    private val byId: MutableMap<String, StoredCredential> = ConcurrentHashMap()
    private val userCredentialIds: MutableMap<String, MutableSet<String>> = ConcurrentHashMap()

    override suspend fun save(credential: StoredCredential) {
        val id = credential.credentialId.value.encoded()
        byId[id] = credential
        userCredentialIds.getOrPut(credential.userId.value.encoded()) { linkedSetOf() }.add(id)
    }

    override suspend fun findById(id: CredentialId): StoredCredential? {
        return byId[id.value.encoded()]
    }

    override suspend fun findByUserId(userId: UserHandle): List<StoredCredential> {
        return userCredentialIds[userId.value.encoded()]
            ?.mapNotNull { byId[it] }
            .orEmpty()
    }

    override suspend fun updateSignCount(id: CredentialId, signCount: Long) {
        val key = id.value.encoded()
        val existing = byId[key] ?: return
        byId[key] = existing.copy(signCount = signCount)
    }
}

public class InMemoryUserAccountStore : UserAccountStore {
    private val byName: MutableMap<String, UserAccount> = ConcurrentHashMap()

    override suspend fun findByName(name: String): UserAccount? {
        return byName[name]
    }

    override suspend fun save(user: UserAccount) {
        byName[user.name] = user
    }
}
