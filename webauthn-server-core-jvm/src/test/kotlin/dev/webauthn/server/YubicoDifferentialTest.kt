package dev.webauthn.server

import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.FinishAssertionOptions
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.data.ByteArray as YubicoByteArray
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.exception.AssertionFailedException
import com.yubico.webauthn.exception.RegistrationFailedException
import dev.webauthn.model.Challenge
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.ValidationResult
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@OptIn(ExperimentalWebAuthnL3Api::class)
class YubicoDifferentialTest {
    @Test
    fun registrationSuccessOutcomeMatchesYubicoServer() = runBlocking {
        val fixture = loadRegistrationFixture()
        val ourResult = runOurRegistration(fixture)
        val yubicoResult = relyingParty(
            fixture = fixture.relyingParty,
            repository = FixtureCredentialRepository(userName = fixture.relyingParty.userName, userHandle = fixture.relyingParty.userHandle),
        ).finishRegistration(
            FinishRegistrationOptions.builder()
                .request(yubicoRegistrationRequest(fixture))
                .response(PublicKeyCredential.parseRegistrationResponseJson(fixture.response.toBrowserCredentialJson()))
                .build(),
        )

        assertTrue(ourResult is ValidationResult.Valid)
        assertEquals(fixture.expected.publicKeyCose, yubicoResult.publicKeyCose.base64Url)
        assertEquals(fixture.expected.credentialId, yubicoResult.keyId.id.base64Url)
        assertEquals(fixture.expected.signCount, yubicoResult.signatureCount)
    }

    @Test
    fun authenticationSuccessOutcomeMatchesYubicoServer() = runBlocking {
        val fixture = loadAuthenticationFixture()
        val ourResult = runOurAuthentication(fixture)
        val yubicoResult = relyingParty(
            fixture = fixture.relyingParty,
            repository = FixtureCredentialRepository(
                userName = fixture.relyingParty.userName,
                userHandle = fixture.relyingParty.userHandle,
                credential = fixture.toRegisteredCredential(),
            ),
        ).finishAssertion(
            FinishAssertionOptions.builder()
                .request(yubicoAssertionRequest(fixture))
                .response(PublicKeyCredential.parseAssertionResponseJson(fixture.response.toBrowserCredentialJson()))
                .build(),
        )

        assertTrue(ourResult is ValidationResult.Valid)
        assertTrue(yubicoResult.isSuccess)
        assertEquals(fixture.expected.credentialId, yubicoResult.credentialId.base64Url)
        assertEquals(fixture.expected.signCount, yubicoResult.signatureCount)
        assertEquals(fixture.relyingParty.userHandle, yubicoResult.userHandle.base64Url)
    }

    @Test
    fun wrongChallengeRejectsInBothImplementations() = runBlocking {
        val fixture = loadAuthenticationFixture()
        val ourResult = runOurAuthentication(
            fixture = fixture,
            sessionChallenge = Challenge.fromBytes(ByteArray(32) { 0x55 }),
        )
        val relyingParty = relyingParty(
            fixture = fixture.relyingParty,
            repository = FixtureCredentialRepository(
                userName = fixture.relyingParty.userName,
                userHandle = fixture.relyingParty.userHandle,
                credential = fixture.toRegisteredCredential(),
            ),
        )

        assertTrue(ourResult is ValidationResult.Invalid)
        assertFailsWith<AssertionFailedException> {
            relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                    .request(yubicoAssertionRequest(fixture, challenge = YubicoByteArray(ByteArray(32) { 0x55 })))
                    .response(PublicKeyCredential.parseAssertionResponseJson(fixture.response.toBrowserCredentialJson()))
                    .build(),
            )
        }
    }

    @Test
    fun wrongOriginRejectsInBothImplementations() = runBlocking {
        val fixture = loadAuthenticationFixture()
        val ourResult = runOurAuthenticationWithOrigin(fixture, "https://example.com")
        val relyingParty = relyingParty(
            fixture = fixture.relyingParty.copy(origin = "https://example.com"),
            repository = FixtureCredentialRepository(
                userName = fixture.relyingParty.userName,
                userHandle = fixture.relyingParty.userHandle,
                credential = fixture.toRegisteredCredential(),
            ),
        )

        assertTrue(ourResult is ValidationResult.Invalid)
        assertFailsWith<AssertionFailedException> {
            relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                    .request(yubicoAssertionRequest(fixture))
                    .response(PublicKeyCredential.parseAssertionResponseJson(fixture.response.toBrowserCredentialJson()))
                    .build(),
            )
        }
    }

    @Test
    fun registrationWrongChallengeRejectsInBothImplementations() = runBlocking {
        val fixture = loadRegistrationFixture()
        val ourResult = runOurRegistrationWithChallenge(
            fixture = fixture,
            challenge = Challenge.fromBytes(ByteArray(32) { 0x11 }),
        )
        val relyingParty = relyingParty(
            fixture = fixture.relyingParty,
            repository = FixtureCredentialRepository(userName = fixture.relyingParty.userName, userHandle = fixture.relyingParty.userHandle),
        )

        assertTrue(ourResult is ValidationResult.Invalid)
        assertFailsWith<RegistrationFailedException> {
            relyingParty.finishRegistration(
                FinishRegistrationOptions.builder()
                    .request(yubicoRegistrationRequest(fixture, challenge = YubicoByteArray(ByteArray(32) { 0x11 })))
                    .response(PublicKeyCredential.parseRegistrationResponseJson(fixture.response.toBrowserCredentialJson()))
                    .build(),
            )
        }
    }

    private suspend fun runOurRegistration(
        fixture: RegistrationCeremonyFixture,
    ): ValidationResult<dev.webauthn.model.RegistrationResponse> {
        return runOurRegistrationWithChallenge(fixture, dev.webauthn.model.Challenge.parseOrThrow(fixture.relyingParty.challenge))
    }

    private suspend fun runOurRegistrationWithChallenge(
        fixture: RegistrationCeremonyFixture,
        challenge: dev.webauthn.model.Challenge,
    ): ValidationResult<dev.webauthn.model.RegistrationResponse> {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        userStore.save(UserAccount(id = fixture.userHandle(), name = fixture.relyingParty.userName, displayName = fixture.relyingParty.userName))
        challengeStore.put(fixture.registrationSession().copy(challenge = challenge))
        val service = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = { ValidationResult.Valid(Unit) },
            rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher(),
        )
        return service.finish(
            RegistrationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.registrationClientData(),
            ),
        )
    }

    private suspend fun runOurAuthentication(
        fixture: AuthenticationCeremonyFixture,
        sessionChallenge: dev.webauthn.model.Challenge = dev.webauthn.model.Challenge.parseOrThrow(fixture.relyingParty.challenge),
    ): ValidationResult<dev.webauthn.model.AuthenticationResponse> {
        return runOurAuthenticationInternal(
            fixture = fixture,
            challenge = sessionChallenge,
            origin = fixture.relyingParty.origin,
        )
    }

    private suspend fun runOurAuthenticationWithOrigin(
        fixture: AuthenticationCeremonyFixture,
        origin: String,
    ): ValidationResult<dev.webauthn.model.AuthenticationResponse> {
        return runOurAuthenticationInternal(
            fixture = fixture,
            challenge = dev.webauthn.model.Challenge.parseOrThrow(fixture.relyingParty.challenge),
            origin = origin,
        )
    }

    private suspend fun runOurAuthenticationInternal(
        fixture: AuthenticationCeremonyFixture,
        challenge: dev.webauthn.model.Challenge,
        origin: String,
    ): ValidationResult<dev.webauthn.model.AuthenticationResponse> {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val userHandle = fixture.userHandle()
        userStore.save(UserAccount(id = userHandle, name = fixture.relyingParty.userName, displayName = fixture.relyingParty.userName))
        credentialStore.save(
            StoredCredential(
                credentialId = dev.webauthn.model.CredentialId.parseOrThrow(fixture.credential.credentialId),
                userId = userHandle,
                rpId = dev.webauthn.model.RpId.parseOrThrow(fixture.relyingParty.rpId),
                publicKeyCose = dev.webauthn.model.CosePublicKey.fromBytes(dev.webauthn.model.Base64UrlBytes.parseOrThrow(fixture.credential.publicKeyCose).bytes()),
                signCount = fixture.credential.signCount,
            ),
        )
        challengeStore.put(
            dev.webauthn.core.ChallengeSession(
                challenge = challenge,
                rpId = dev.webauthn.model.RpId.parseOrThrow(fixture.relyingParty.rpId),
                origin = dev.webauthn.model.Origin.parseOrThrow(origin),
                userName = fixture.relyingParty.userName,
                createdAtEpochMs = 0L,
                expiresAtEpochMs = Long.MAX_VALUE,
                type = dev.webauthn.core.CeremonyType.AUTHENTICATION,
            ),
        )
        val service = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = dev.webauthn.server.crypto.JvmSignatureVerifier(),
            rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher(),
        )
        return service.finish(
            AuthenticationFinishRequest(
                responseDto = fixture.response.toDto(),
                clientData = fixture.authenticationClientData(),
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

    private fun relyingParty(
        fixture: CeremonyRelyingPartyFixture,
        repository: FixtureCredentialRepository,
    ): RelyingParty {
        return RelyingParty.builder()
            .identity(
                RelyingPartyIdentity.builder()
                    .id(fixture.rpId)
                    .name("Example")
                    .build(),
            )
            .credentialRepository(repository)
            .origins(setOf(fixture.origin))
            .allowUntrustedAttestation(true)
            .build()
    }

    private fun yubicoRegistrationRequest(
        fixture: RegistrationCeremonyFixture,
        challenge: YubicoByteArray = YubicoByteArray.fromBase64Url(fixture.relyingParty.challenge),
    ): PublicKeyCredentialCreationOptions {
        return PublicKeyCredentialCreationOptions.builder()
            .rp(
                RelyingPartyIdentity.builder()
                    .id(fixture.relyingParty.rpId)
                    .name("Example")
                    .build(),
            )
            .user(
                UserIdentity.builder()
                    .name(fixture.relyingParty.userName)
                    .displayName(fixture.relyingParty.userName)
                    .id(YubicoByteArray.fromBase64Url(fixture.relyingParty.userHandle))
                    .build(),
            )
            .challenge(challenge)
            .pubKeyCredParams(listOf(PublicKeyCredentialParameters.ES256))
            .build()
    }

    private fun yubicoAssertionRequest(
        fixture: AuthenticationCeremonyFixture,
        challenge: YubicoByteArray = YubicoByteArray.fromBase64Url(fixture.relyingParty.challenge),
    ): AssertionRequest {
        return AssertionRequest.builder()
            .publicKeyCredentialRequestOptions(
                PublicKeyCredentialRequestOptions.builder()
                    .challenge(challenge)
                    .rpId(fixture.relyingParty.rpId)
                    .allowCredentials(
                        listOf(
                            PublicKeyCredentialDescriptor.builder()
                                .id(YubicoByteArray.fromBase64Url(fixture.credential.credentialId))
                                .type(com.yubico.webauthn.data.PublicKeyCredentialType.PUBLIC_KEY)
                                .build(),
                        ),
                    )
                    .build(),
            )
            .username(fixture.relyingParty.userName)
            .userHandle(YubicoByteArray.fromBase64Url(fixture.relyingParty.userHandle))
            .build()
    }

    private fun AuthenticationCeremonyFixture.toRegisteredCredential(): RegisteredCredential {
        return RegisteredCredential.builder()
            .credentialId(YubicoByteArray.fromBase64Url(credential.credentialId))
            .userHandle(YubicoByteArray.fromBase64Url(relyingParty.userHandle))
            .publicKeyCose(YubicoByteArray.fromBase64Url(credential.publicKeyCose))
            .signatureCount(credential.signCount)
            .build()
    }

    private class FixtureCredentialRepository(
        private val userName: String,
        private val userHandle: String,
        private val credential: RegisteredCredential? = null,
    ) : CredentialRepository {
        override fun getCredentialIdsForUsername(username: String): Set<PublicKeyCredentialDescriptor> {
            if (username != userName || credential == null) return emptySet()
            return setOf(
                PublicKeyCredentialDescriptor.builder()
                    .id(credential.credentialId)
                    .type(com.yubico.webauthn.data.PublicKeyCredentialType.PUBLIC_KEY)
                    .build(),
            )
        }

        override fun getUserHandleForUsername(username: String): java.util.Optional<YubicoByteArray> {
            return if (username == userName) {
                java.util.Optional.of(YubicoByteArray.fromBase64Url(userHandle))
            } else {
                java.util.Optional.empty()
            }
        }

        override fun getUsernameForUserHandle(userHandle: YubicoByteArray): java.util.Optional<String> {
            return if (userHandle.base64Url == this.userHandle) java.util.Optional.of(userName) else java.util.Optional.empty()
        }

        override fun lookup(
            credentialId: YubicoByteArray,
            userHandle: YubicoByteArray,
        ): java.util.Optional<RegisteredCredential> {
            return if (
                credential != null &&
                credential.credentialId == credentialId &&
                userHandle.base64Url == this.userHandle
            ) {
                java.util.Optional.of(credential)
            } else {
                java.util.Optional.empty()
            }
        }

        override fun lookupAll(credentialId: YubicoByteArray): Set<RegisteredCredential> {
            return if (credential?.credentialId == credentialId) setOf(credential) else emptySet()
        }
    }
}
