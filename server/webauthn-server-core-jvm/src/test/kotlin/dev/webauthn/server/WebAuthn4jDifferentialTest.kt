package dev.webauthn.server

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.RegistrationData
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalWebAuthnL3Api::class)
@Suppress("DEPRECATION")
class WebAuthn4jDifferentialTest {
    private val manager = WebAuthnManager.createNonStrictWebAuthnManager()

    @Test
    fun registrationSuccessOutcomeMatchesWebAuthn4j() = runBlocking {
        val fixture = loadRegistrationFixture()
        val ourResult = runOurRegistration(fixture)
        val theirResult = manager.validate(
            RegistrationRequest(
                base64Url(fixture.response.attestationObject),
                base64Url(fixture.response.clientDataJson),
            ),
            RegistrationParameters(
                fixture.serverProperty(),
                listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                false,
                false,
            ),
        )
        val attestationObject = requireNotNull(theirResult.attestationObject)
        val authenticatorData = attestationObject.authenticatorData
        val attestedCredentialData = requireNotNull(authenticatorData.attestedCredentialData)
        val coseKey = requireNotNull(attestedCredentialData.getCOSEKey())
        val coseAlgorithm = requireNotNull(coseKey.algorithm).value

        assertTrue(ourResult is ValidationResult.Valid)
        assertEquals(ourResult.value.attestedCredentialData.cosePublicKey.encoded(), fixture.expected.publicKeyCose)
        assertEquals(fixture.expected.alg.toLong(), coseAlgorithm)
        assertContentEquals(
            ourResult.value.attestedCredentialData.credentialId.value.bytes(),
            attestedCredentialData.credentialId,
        )
        assertEquals(
            ourResult.value.rawAuthenticatorData.signCount,
            authenticatorData.signCount,
        )
    }

    @Test
    fun authenticationSuccessOutcomeMatchesWebAuthn4j() = runBlocking {
        val authenticationFixture = loadAuthenticationFixture()
        val ourResult = runOurAuthentication(authenticationFixture)
        val registrationData = requireSuccessfulRegistration(loadRegistrationFixture())
        val credentialRecord = CredentialRecordImpl(
            requireNotNull(registrationData.attestationObject),
            registrationData.collectedClientData,
            registrationData.clientExtensions,
            emptySet(),
        )
        val theirResult = manager.validate(
            AuthenticationRequest(
                base64Url(authenticationFixture.credential.credentialId),
                base64Url(authenticationFixture.relyingParty.userHandle),
                base64Url(authenticationFixture.response.authenticatorData),
                base64Url(authenticationFixture.response.clientDataJson),
                base64Url(authenticationFixture.response.signature),
            ),
            AuthenticationParameters(
                authenticationFixture.serverProperty(),
                credentialRecord,
                listOf(base64Url(authenticationFixture.credential.credentialId)),
                false,
                false,
            ),
        )
        val authenticatorData = requireNotNull(theirResult.authenticatorData)
        val credentialId = requireNotNull(theirResult.credentialId)
        val credentialCoseKey = requireNotNull(credentialRecord.attestedCredentialData.getCOSEKey())
        val credentialAlgorithm = requireNotNull(credentialCoseKey.algorithm).value

        assertTrue(ourResult is ValidationResult.Valid)
        assertEquals(
            ourResult.value.authenticatorData.signCount,
            authenticatorData.signCount,
        )
        assertEquals(
            ourResult.value.credentialId.value.encoded(),
            Base64UrlBytes.fromBytes(credentialId).encoded(),
        )
        assertEquals(authenticationFixture.expected.alg.toLong(), credentialAlgorithm)
    }

    @Test
    fun wrongChallengeRejectsInBothImplementations() = runBlocking {
        val fixture = loadAuthenticationFixture()
        val ourResult = runOurAuthentication(
            fixture = fixture,
            sessionChallenge = Challenge.fromBytes(ByteArray(32) { 0x55 }),
        )
        val registrationData = requireSuccessfulRegistration(loadRegistrationFixture())
        val credentialRecord = CredentialRecordImpl(
            requireNotNull(registrationData.attestationObject),
            registrationData.collectedClientData,
            registrationData.clientExtensions,
            emptySet(),
        )
        val webauthn4jFailure = runCatching {
            manager.validate(
                AuthenticationRequest(
                    base64Url(fixture.credential.credentialId),
                    base64Url(fixture.relyingParty.userHandle),
                    base64Url(fixture.response.authenticatorData),
                    base64Url(fixture.response.clientDataJson),
                    base64Url(fixture.response.signature),
                ),
                AuthenticationParameters(
                    ServerProperty(
                        Origin(fixture.relyingParty.origin),
                        fixture.relyingParty.rpId,
                        DefaultChallenge(ByteArray(32) { 0x55 }),
                    ),
                    credentialRecord,
                    listOf(base64Url(fixture.credential.credentialId)),
                    false,
                    false,
                ),
            )
        }

        assertTrue(ourResult is ValidationResult.Invalid)
        assertTrue(webauthn4jFailure.isFailure)
    }

    private fun requireSuccessfulRegistration(fixture: RegistrationCeremonyFixture): RegistrationData {
        return manager.validate(
            RegistrationRequest(
                base64Url(fixture.response.attestationObject),
                base64Url(fixture.response.clientDataJson),
            ),
            RegistrationParameters(
                fixture.serverProperty(),
                listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                false,
                false,
            ),
        )
    }

    private suspend fun runOurRegistration(
        fixture: RegistrationCeremonyFixture,
    ): ValidationResult<dev.webauthn.model.RegistrationResponse> {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        userStore.save(UserAccount(id = UserHandle.parseOrThrow(fixture.relyingParty.userHandle), name = fixture.relyingParty.userName, displayName = fixture.relyingParty.userName))
        challengeStore.put(
            ChallengeSession(
                challenge = Challenge.parseOrThrow(fixture.relyingParty.challenge),
                rpId = RpId.parseOrThrow(fixture.relyingParty.rpId),
                origin = dev.webauthn.model.Origin.parseOrThrow(fixture.relyingParty.origin),
                userName = fixture.relyingParty.userName,
                createdAtEpochMs = 0L,
                expiresAtEpochMs = Long.MAX_VALUE,
                type = CeremonyType.REGISTRATION,
            ),
        )
        val service = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = JvmRpIdHasher(),
        )
        return service.finish(
            RegistrationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = CollectedClientData(
                    type = "webauthn.create",
                    challenge = Challenge.parseOrThrow(fixture.relyingParty.challenge),
                    origin = dev.webauthn.model.Origin.parseOrThrow(fixture.relyingParty.origin),
                ),
            ),
        )
    }

    private suspend fun runOurAuthentication(
        fixture: AuthenticationCeremonyFixture,
        sessionChallenge: Challenge = Challenge.parseOrThrow(fixture.relyingParty.challenge),
    ): ValidationResult<dev.webauthn.model.AuthenticationResponse> {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val userHandle = UserHandle.parseOrThrow(fixture.relyingParty.userHandle)
        userStore.save(UserAccount(id = userHandle, name = fixture.relyingParty.userName, displayName = fixture.relyingParty.userName))
        credentialStore.save(
            StoredCredential(
                credentialId = CredentialId.parseOrThrow(fixture.credential.credentialId),
                userId = userHandle,
                rpId = RpId.parseOrThrow(fixture.relyingParty.rpId),
                publicKeyCose = CosePublicKey.fromBytes(base64Url(fixture.credential.publicKeyCose)),
                signCount = fixture.credential.signCount,
            ),
        )
        challengeStore.put(
            ChallengeSession(
                challenge = sessionChallenge,
                rpId = RpId.parseOrThrow(fixture.relyingParty.rpId),
                origin = dev.webauthn.model.Origin.parseOrThrow(fixture.relyingParty.origin),
                userName = fixture.relyingParty.userName,
                createdAtEpochMs = 0L,
                expiresAtEpochMs = Long.MAX_VALUE,
                type = CeremonyType.AUTHENTICATION,
            ),
        )
        val service = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = JvmSignatureVerifier(),
            rpIdHasher = JvmRpIdHasher(),
        )
        return service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = Challenge.parseOrThrow(fixture.relyingParty.challenge),
                    origin = dev.webauthn.model.Origin.parseOrThrow(fixture.relyingParty.origin),
                ),
            ),
        )
    }

    private fun loadRegistrationFixture(): RegistrationCeremonyFixture =
        loadRegistrationCeremonyFixture(
            path = "fixtures/ceremony/registration-android-none.json",
            classLoader = javaClass.classLoader,
        )

    private fun loadAuthenticationFixture(): AuthenticationCeremonyFixture =
        loadAuthenticationCeremonyFixture(
            path = "fixtures/ceremony/authentication-android-es256.json",
            classLoader = javaClass.classLoader,
        )

    private fun RegistrationCeremonyFixture.serverProperty(): ServerProperty =
        ServerProperty(
            Origin(relyingParty.origin),
            relyingParty.rpId,
            DefaultChallenge(base64Url(relyingParty.challenge)),
        )

    private fun AuthenticationCeremonyFixture.serverProperty(): ServerProperty =
        ServerProperty(
            Origin(relyingParty.origin),
            relyingParty.rpId,
            DefaultChallenge(base64Url(relyingParty.challenge)),
        )

    private fun base64Url(value: String): ByteArray = Base64UrlBytes.parseOrThrow(value).bytes()
}
