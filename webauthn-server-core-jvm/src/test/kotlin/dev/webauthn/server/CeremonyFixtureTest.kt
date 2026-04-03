package dev.webauthn.server

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.WebAuthnDtoMapper
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalWebAuthnL3Api::class)
class CeremonyFixtureTest {
    @Test
    fun registrationFixtureSucceedsOfflineAndStoresExpectedCredential() = runBlocking {
        val fixture = loadRegistrationCeremonyFixture(
            path = "fixtures/ceremony/registration-android-none.json",
            classLoader = javaClass.classLoader,
        )
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val service = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = JvmRpIdHasher(),
        )

        userStore.save(UserAccount(id = fixture.userHandle(), name = fixture.relyingParty.userName, displayName = fixture.relyingParty.userName))
        challengeStore.put(fixture.registrationSession())

        val parsed = WebAuthnDtoMapper.toModel(fixture.response.toDto())
        assertTrue(parsed is ValidationResult.Valid)
        assertEquals(fixture.expected.signCount, parsed.value.rawAuthenticatorData.signCount)
        assertEquals(fixture.expected.credentialId, parsed.value.attestedCredentialData.credentialId.value.encoded())
        assertEquals(fixture.expected.publicKeyCose, parsed.value.attestedCredentialData.cosePublicKey.encoded())

        val result = service.finish(
            RegistrationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.registrationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Valid)
        val stored = credentialStore.findById(CredentialId.parseOrThrow(fixture.expected.credentialId))
        assertEquals(fixture.expected.signCount, stored?.signCount)
        assertEquals(fixture.expected.publicKeyCose, stored?.publicKeyCose?.encoded())
    }

    @Test
    fun authenticationFixtureSucceedsOfflineAndUsesRealSignature() = runBlocking {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val service = authenticationServiceFor(fixture)

        val result = service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.authenticationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals(fixture.expected.signCount, result.value.authenticatorData.signCount)
        assertEquals(fixture.expected.credentialId, result.value.credentialId.value.encoded())
        assertEquals(fixture.relyingParty.userHandle, result.value.userHandle?.value?.encoded())
    }

    @Test
    fun authenticationFixtureRejectsWrongChallenge() = runBlocking {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val service = authenticationServiceFor(
            fixture = fixture,
            sessionChallenge = Challenge.fromBytes(ByteArray(32) { 0x44 }),
        )

        val result = service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.authenticationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("challenge", result.errors.single().field)
    }

    @Test
    fun authenticationFixtureRejectsWrongOrigin() = runBlocking {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val service = authenticationServiceFor(
            fixture = fixture,
            sessionOrigin = Origin.parseOrThrow("https://example.com"),
        )

        val result = service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.authenticationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("origin", result.errors.single().field)
    }

    @Test
    fun authenticationFixtureRejectsRpIdHashMismatch() = runBlocking {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val service = authenticationServiceFor(
            fixture = fixture,
            sessionRpId = RpId.parseOrThrow("example.com"),
        )

        val result = service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.authenticationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("authenticatorData.rpIdHash", result.errors.single().field)
    }

    @Test
    fun authenticationFixtureRejectsUnsupportedStoredCredentialAlgorithm() = runBlocking {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val service = authenticationServiceFor(
            fixture = fixture,
            storedPublicKeyCose = Base64UrlBytes.fromBytes(
                cborMap(
                    cborInt(1L) to cborInt(1L),
                    cborInt(3L) to cborInt(-8L),
                    cborInt(-1L) to cborInt(6L),
                    cborInt(-2L) to cborBytes(ByteArray(32) { it.toByte() }),
                ),
            ).encoded(),
        )

        val result = service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.authenticationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("signature", result.errors.single().field)
    }

    @Test
    fun authenticationFixtureRejectsMalformedAuthenticatorData() = runBlocking {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val service = authenticationServiceFor(fixture)

        val result = service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.copy(
                    authenticatorData = Base64UrlBytes.fromBytes(ByteArray(10) { 0x01 }).encoded(),
                ).toDto(),
                clientData = fixture.authenticationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("response.authenticatorData", result.errors.single().field)
    }

    @Test
    fun registrationFixtureRejectsMalformedCredentialPublicKey() = runBlocking {
        val fixture = loadRegistrationCeremonyFixture(
            path = "fixtures/ceremony/registration-android-none.json",
            classLoader = javaClass.classLoader,
        )
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val service = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = JvmRpIdHasher(),
        )

        userStore.save(UserAccount(id = fixture.userHandle(), name = fixture.relyingParty.userName, displayName = fixture.relyingParty.userName))
        challengeStore.put(fixture.registrationSession())

        val malformedAttestationObject = noneAttestationObject(
            authData = registrationAuthenticatorDataBytes(
                rpIdHash = Base64UrlBytes.parseOrThrow("1yxH9d_LMT9HH9R86tjNMYA5bPTEoE_v8MJkyJ-ScWo").bytes(),
                flags = 0x5D,
                signCount = 0,
                aaguid = Base64UrlBytes.parseOrThrow(fixture.expected.aaguid).bytes(),
                credentialId = Base64UrlBytes.parseOrThrow(fixture.expected.credentialId).bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01),
            ),
        )

        val result = service.finish(
            RegistrationFinishRequest(
                responseDto = fixture.response.copy(
                    attestationObject = Base64UrlBytes.fromBytes(malformedAttestationObject).encoded(),
                ).toDto(),
                clientData = fixture.registrationClientData(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
        assertEquals("attestationObject.authData", result.errors.single().field)
    }

    @Test
    fun buildSignedAuthenticationDataMatchesRawAuthenticatorDataPlusClientDataHash() {
        val fixture = loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )
        val parsed = WebAuthnDtoMapper.toModel(fixture.response.toDto())
        assertTrue(parsed is ValidationResult.Valid)

        val signedData = buildSignedAuthenticationData(parsed.value)
        val expected = Base64UrlBytes.parseOrThrow(fixture.response.authenticatorData).bytes() +
            MessageDigest.getInstance("SHA-256").digest(Base64UrlBytes.parseOrThrow(fixture.response.clientDataJson).bytes())

        assertContentEquals(expected, signedData)
    }

    private suspend fun authenticationServiceFor(
        fixture: AuthenticationCeremonyFixture,
        sessionChallenge: Challenge = Challenge.parseOrThrow(fixture.relyingParty.challenge),
        sessionOrigin: Origin = Origin.parseOrThrow(fixture.relyingParty.origin),
        sessionRpId: RpId = RpId.parseOrThrow(fixture.relyingParty.rpId),
        storedPublicKeyCose: String = fixture.credential.publicKeyCose,
    ): AuthenticationService {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        userStore.save(
            UserAccount(
                id = fixture.userHandle(),
                name = fixture.relyingParty.userName,
                displayName = fixture.relyingParty.userName,
            ),
        )
        credentialStore.save(
            StoredCredential(
                credentialId = CredentialId.parseOrThrow(fixture.credential.credentialId),
                userId = fixture.userHandle(),
                rpId = sessionRpId,
                publicKeyCose = CosePublicKey.fromBytes(Base64UrlBytes.parseOrThrow(storedPublicKeyCose).bytes()),
                signCount = fixture.credential.signCount,
            ),
        )
        challengeStore.put(
            ChallengeSession(
                challenge = sessionChallenge,
                rpId = sessionRpId,
                origin = sessionOrigin,
                userName = fixture.relyingParty.userName,
                createdAtEpochMs = 0L,
                expiresAtEpochMs = Long.MAX_VALUE,
                type = CeremonyType.AUTHENTICATION,
            ),
        )
        return AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = JvmSignatureVerifier(),
            rpIdHasher = JvmRpIdHasher(),
        )
    }

    private fun registrationAuthenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
        aaguid: ByteArray,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
    ): ByteArray {
        return rpIdHash +
            byteArrayOf(flags.toByte()) +
            uint32(signCount) +
            aaguid +
            uint16(credentialId.size) +
            credentialId +
            cosePublicKey
    }

    private fun noneAttestationObject(authData: ByteArray): ByteArray {
        return cborMap(
            cborText("fmt") to cborText("none"),
            cborText("authData") to cborBytes(authData),
            cborText("attStmt") to cborMap(),
        )
    }

    private fun cborMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray {
        var result = cborHeader(5, entries.size)
        entries.forEach { (key, value) -> result += key + value }
        return result
    }

    private fun cborInt(value: Long): ByteArray =
        if (value >= 0) cborHeaderLong(0, value) else cborHeaderLong(1, -1L - value)

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return cborHeader(3, bytes.size) + bytes
    }

    private fun cborBytes(value: ByteArray): ByteArray = cborHeader(2, value.size) + value

    private fun cborHeader(majorType: Int, length: Int): ByteArray = cborHeaderLong(majorType, length.toLong())

    private fun cborHeaderLong(majorType: Int, length: Long): ByteArray {
        val prefix = majorType shl 5
        return when {
            length < 24 -> byteArrayOf((prefix or length.toInt()).toByte())
            length < 256 -> byteArrayOf((prefix or 24).toByte(), length.toByte())
            else -> error("Test helper only supports short lengths")
        }
    }

    private fun uint16(value: Int): ByteArray {
        return byteArrayOf(
            ((value ushr 8) and 0xFF).toByte(),
            (value and 0xFF).toByte(),
        )
    }

    private fun uint32(value: Long): ByteArray {
        return byteArrayOf(
            ((value ushr 24) and 0xFF).toByte(),
            ((value ushr 16) and 0xFF).toByte(),
            ((value ushr 8) and 0xFF).toByte(),
            (value and 0xFF).toByte(),
        )
    }
}
