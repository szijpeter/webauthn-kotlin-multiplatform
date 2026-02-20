package dev.webauthn.server

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.server.crypto.JvmRpIdHasher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

abstract class StoreContractTestBase {

    protected val rpId: RpId = RpId.parseOrThrow("example.com")
    protected val origin: Origin = Origin.parseOrThrow("https://example.com")
    protected val rpIdHasher = JvmRpIdHasher()

    protected class StoreFixture(
        val challengeStore: ChallengeStore,
        val credentialStore: CredentialStore,
        val userStore: UserAccountStore,
        private val cleanup: () -> Unit = {},
    ) : AutoCloseable {
        override fun close() {
            cleanup()
        }
    }

    protected abstract fun createStoreFixture(): StoreFixture

    @Test
    fun concurrentRegistrationFinishOnlyAllowsOneSuccess() = runBlocking {
        withStoreFixture { fixture ->
            val now = 10_000L
            val registrationService = RegistrationService(
                challengeStore = fixture.challengeStore,
                credentialStore = fixture.credentialStore,
                userAccountStore = fixture.userStore,
                attestationVerifier = { ValidationResult.Valid(Unit) },
                rpIdHasher = rpIdHasher,
                nowEpochMs = { now },
            )

            val challenge = Challenge.fromBytes(ByteArray(32) { 1 })
            val userHandle = UserHandle.fromBytes(ByteArray(16) { 2 })
            val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })

            fixture.userStore.save(UserAccount(userHandle, "alice", "Alice"))
            fixture.challengeStore.put(
                ChallengeSession(
                    challenge = challenge,
                    rpId = rpId,
                    origin = origin,
                    userName = "alice",
                    createdAtEpochMs = now,
                    expiresAtEpochMs = now + 60_000,
                    type = CeremonyType.REGISTRATION,
                ),
            )

            val attestationObject = attestationObjectWithAuthData(
                registrationAuthenticatorDataBytes(
                    rpIdHash = rpIdHasher.hashRpId("example.com"),
                    flags = 0x41,
                    signCount = 1,
                    credentialId = credentialId.value.bytes(),
                    cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
                ),
            )

            val request = RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = credentialId.value.encoded(),
                    rawId = credentialId.value.encoded(),
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.create",
                    challenge = challenge,
                    origin = origin,
                ),
            )

            val outcomes = coroutineScope {
                (1..10).map {
                    async { registrationService.finish(request) }
                }.awaitAll()
            }

            val successes = outcomes.count { it is ValidationResult.Valid }
            assertEquals(1, successes, "Exactly one registration should succeed")

            val errors = outcomes.filterIsInstance<ValidationResult.Invalid>().flatMap { it.errors }
            assertTrue(errors.all { it.message.contains("challenge") }, "Errors should be challenge-related")
        }
    }

    @Test
    fun concurrentAuthenticationFinishOnlyAllowsOneSuccess() = runBlocking {
        withStoreFixture { fixture ->
            val now = 10_000L
            val authenticationService = AuthenticationService(
                challengeStore = fixture.challengeStore,
                credentialStore = fixture.credentialStore,
                userAccountStore = fixture.userStore,
                signatureVerifier = SignatureVerifier { _, _, _, _ -> true },
                rpIdHasher = rpIdHasher,
                nowEpochMs = { now },
            )

            val challenge = Challenge.fromBytes(ByteArray(32) { 3 })
            val userHandle = UserHandle.fromBytes(ByteArray(16) { 4 })
            val credentialId = CredentialId.fromBytes(ByteArray(16) { 5 })

            fixture.userStore.save(UserAccount(userHandle, "bob", "Bob"))
            fixture.credentialStore.save(StoredCredential(credentialId, userHandle, rpId, byteArrayOf(1, 2, 3), 0))
            fixture.challengeStore.put(
                ChallengeSession(
                    challenge = challenge,
                    rpId = rpId,
                    origin = origin,
                    userName = "bob",
                    createdAtEpochMs = now,
                    expiresAtEpochMs = now + 60_000,
                    type = CeremonyType.AUTHENTICATION,
                ),
            )

            val authData = authenticationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x01,
                signCount = 2,
            )

            val request = AuthenticationFinishRequest(
                responseDto = AuthenticationResponseDto(
                    id = credentialId.value.encoded(),
                    rawId = credentialId.value.encoded(),
                    response = AuthenticationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)).encoded(),
                        authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                        signature = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)).encoded(),
                        userHandle = null,
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = challenge,
                    origin = origin,
                ),
            )

            val outcomes = coroutineScope {
                (1..10).map {
                    async { authenticationService.finish(request) }
                }.awaitAll()
            }

            val successes = outcomes.count { it is ValidationResult.Valid }
            assertEquals(1, successes, "Exactly one authentication should succeed")

            val errors = outcomes.filterIsInstance<ValidationResult.Invalid>().flatMap { it.errors }
            assertTrue(errors.all { it.message.contains("challenge") }, "Errors should be challenge-related")
        }
    }

    @Test
    fun sequentialRegistrationReplayIsBlocked() = runBlocking {
        withStoreFixture { fixture ->
            val now = 10_000L
            val registrationService = RegistrationService(
                challengeStore = fixture.challengeStore,
                credentialStore = fixture.credentialStore,
                userAccountStore = fixture.userStore,
                attestationVerifier = { ValidationResult.Valid(Unit) },
                rpIdHasher = rpIdHasher,
                nowEpochMs = { now },
            )

            val challenge = Challenge.fromBytes(ByteArray(32) { 9 })
            fixture.userStore.save(UserAccount(UserHandle.fromBytes(ByteArray(16) { 9 }), "alice", "Alice"))
            fixture.challengeStore.put(
                ChallengeSession(
                    challenge = challenge,
                    rpId = rpId,
                    origin = origin,
                    userName = "alice",
                    createdAtEpochMs = now,
                    expiresAtEpochMs = now + 60_000,
                    type = CeremonyType.REGISTRATION,
                ),
            )

            val request = RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = "YWFh",
                    rawId = "YWFh",
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(
                            attestationObjectWithAuthData(
                                registrationAuthenticatorDataBytes(
                                    rpIdHash = rpIdHasher.hashRpId("example.com"),
                                    flags = 0x41,
                                    signCount = 1,
                                    credentialId = byteArrayOf(1),
                                    cosePublicKey = byteArrayOf(0xA1.toByte(), 1, 2),
                                ),
                            ),
                        ).encoded(),
                    ),
                ),
                clientData = CollectedClientData("webauthn.create", challenge, origin),
            )

            val first = registrationService.finish(request)
            assertTrue(first is ValidationResult.Valid, "First attempt should succeed")

            val second = registrationService.finish(request)
            assertTrue(second is ValidationResult.Invalid, "Second attempt should fail")
            assertTrue(second.errors.any { it.message.contains("challenge") }, "Error should be challenge-related")
        }
    }

    @Test
    fun sequentialAuthenticationReplayIsBlocked() = runBlocking {
        withStoreFixture { fixture ->
            val now = 10_000L
            val authenticationService = AuthenticationService(
                challengeStore = fixture.challengeStore,
                credentialStore = fixture.credentialStore,
                userAccountStore = fixture.userStore,
                signatureVerifier = SignatureVerifier { _, _, _, _ -> true },
                rpIdHasher = rpIdHasher,
                nowEpochMs = { now },
            )

            val challenge = Challenge.fromBytes(ByteArray(32) { 8 })
            val credentialId = CredentialId.fromBytes(ByteArray(16) { 8 })
            val userHandle = UserHandle.fromBytes(ByteArray(16) { 8 })
            fixture.userStore.save(UserAccount(userHandle, "bob", "Bob"))
            fixture.credentialStore.save(StoredCredential(credentialId, userHandle, rpId, byteArrayOf(1), 0))
            fixture.challengeStore.put(
                ChallengeSession(
                    challenge = challenge,
                    rpId = rpId,
                    origin = origin,
                    userName = "bob",
                    createdAtEpochMs = now,
                    expiresAtEpochMs = now + 60_000,
                    type = CeremonyType.AUTHENTICATION,
                ),
            )

            val request = AuthenticationFinishRequest(
                responseDto = AuthenticationResponseDto(
                    id = credentialId.value.encoded(),
                    rawId = credentialId.value.encoded(),
                    response = AuthenticationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1)).encoded(),
                        authenticatorData = Base64UrlBytes.fromBytes(
                            authenticationAuthenticatorDataBytes(rpIdHasher.hashRpId("example.com"), 0x01, 1),
                        ).encoded(),
                        signature = "YWFh",
                        userHandle = null,
                    ),
                ),
                clientData = CollectedClientData("webauthn.get", challenge, origin),
            )

            val first = authenticationService.finish(request)
            assertTrue(first is ValidationResult.Valid, "First attempt should succeed")

            val second = authenticationService.finish(request)
            assertTrue(second is ValidationResult.Invalid, "Second attempt should fail")
            assertTrue(second.errors.any { it.message.contains("challenge") }, "Error should be challenge-related")
        }
    }

    protected fun authenticationAuthenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
    ): ByteArray = concat(rpIdHash, byteArrayOf(flags.toByte()), uint32(signCount))

    protected fun registrationAuthenticatorDataBytes(
        rpIdHash: ByteArray = ByteArray(32) { 0x10 },
        flags: Int,
        signCount: Long,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
    ): ByteArray = concat(
        rpIdHash,
        byteArrayOf(flags.toByte()),
        uint32(signCount),
        ByteArray(16) { 0x22 },
        uint16(credentialId.size),
        credentialId,
        cosePublicKey,
    )

    protected fun attestationObjectWithAuthData(authData: ByteArray): ByteArray = cborMap(
        "fmt" to cborText("none"),
        "authData" to cborBytes(authData),
        "attStmt" to cborMap(),
    )

    private suspend fun <T> withStoreFixture(block: suspend (StoreFixture) -> T): T {
        val fixture = createStoreFixture()
        return try {
            block(fixture)
        } finally {
            fixture.close()
        }
    }

    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        entries.forEach { (key, value) -> result = concat(result, cborText(key), value) }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return concat(cborHeader(majorType = 3, length = bytes.size), bytes)
    }

    private fun cborBytes(value: ByteArray): ByteArray =
        concat(cborHeader(majorType = 2, length = value.size), value)

    private fun cborHeader(majorType: Int, length: Int): ByteArray =
        if (length < 24) byteArrayOf(((majorType shl 5) or length).toByte())
        else byteArrayOf(((majorType shl 5) or 24).toByte(), length.toByte())

    private fun uint16(value: Int): ByteArray =
        byteArrayOf(((value ushr 8) and 0xFF).toByte(), (value and 0xFF).toByte())

    private fun uint32(value: Long): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    private fun concat(vararg chunks: ByteArray): ByteArray {
        val size = chunks.sumOf { it.size }
        val result = ByteArray(size)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(result, destinationOffset = offset)
            offset += chunk.size
        }
        return result
    }
}
