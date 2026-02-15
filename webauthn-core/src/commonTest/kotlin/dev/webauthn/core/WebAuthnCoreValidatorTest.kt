package dev.webauthn.core

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebAuthnCoreValidatorTest {
    @Test
    fun clientDataFailsForTypeMismatch() {
        val challenge = sampleChallenge(1)
        val result = WebAuthnCoreValidator.validateClientData(
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = challenge,
                origin = sampleOrigin(),
            ),
            expectedType = "webauthn.create",
            expectedChallenge = challenge.value.encoded(),
            expectedOrigin = sampleOrigin(),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun clientDataFailsForChallengeMismatch() {
        val result = WebAuthnCoreValidator.validateClientData(
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = sampleChallenge(2),
                origin = sampleOrigin(),
            ),
            expectedType = "webauthn.get",
            expectedChallenge = sampleChallenge(3).value.encoded(),
            expectedOrigin = sampleOrigin(),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun clientDataFailsForOriginMismatch() {
        val result = WebAuthnCoreValidator.validateClientData(
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = sampleChallenge(4),
                origin = Origin.parseOrThrow("https://example.com"),
            ),
            expectedType = "webauthn.get",
            expectedChallenge = sampleChallenge(4).value.encoded(),
            expectedOrigin = Origin.parseOrThrow("https://login.example.com"),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun clientDataPassesForExactMatch() {
        val challenge = sampleChallenge(5)
        val result = WebAuthnCoreValidator.validateClientData(
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = challenge,
                origin = sampleOrigin(),
            ),
            expectedType = "webauthn.get",
            expectedChallenge = challenge.value.encoded(),
            expectedOrigin = sampleOrigin(),
        )

        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticatorDataFailsForInvalidRpIdHashLength() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(31),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                signCount = 1,
            ),
            previousSignCount = 0,
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticatorDataFailsForMissingUserPresenceFlag() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = 0,
                signCount = 1,
            ),
            previousSignCount = 0,
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticatorDataFailsForNonIncreasingSignCount() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                signCount = 5,
            ),
            previousSignCount = 5,
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticatorDataAllowsZeroCounterCases() {
        val bothZero = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                signCount = 0,
            ),
            previousSignCount = 0,
        )
        val currentZero = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                signCount = 0,
            ),
            previousSignCount = 10,
        )

        assertTrue(bothZero is ValidationResult.Valid)
        assertTrue(currentZero is ValidationResult.Valid)
    }

    @Test
    fun authenticatorDataFailsWhenUvRequiredButNotSet() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                signCount = 1,
            ),
            previousSignCount = 0,
            uvPolicy = UserVerificationPolicy.REQUIRED,
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticatorDataPassesWhenUvRequiredAndSet() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG or WebAuthnCoreValidator.USER_VERIFICATION_FLAG,
                signCount = 1,
            ),
            previousSignCount = 0,
            uvPolicy = UserVerificationPolicy.REQUIRED,
        )

        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticatorDataPassesWhenUvPreferredAndNotSet() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                signCount = 1,
            ),
            previousSignCount = 0,
            uvPolicy = UserVerificationPolicy.PREFERRED,
        )

        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun authenticatorDataFailsWhenBackupStateSetWithoutBackupEligible() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG or WebAuthnCoreValidator.BACKUP_STATE_FLAG,
                signCount = 1,
            ),
            previousSignCount = 0,
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticatorDataPassesWhenBackupStateAndEligibleBothSet() {
        val result = WebAuthnCoreValidator.validateAuthenticatorData(
            data = AuthenticatorData(
                rpIdHash = ByteArray(32),
                flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG or
                    WebAuthnCoreValidator.BACKUP_ELIGIBLE_FLAG or
                    WebAuthnCoreValidator.BACKUP_STATE_FLAG,
                signCount = 1,
            ),
            previousSignCount = 0,
        )

        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun requireAllowedCredentialPassesWhenAllowListIsEmpty() {
        val result = WebAuthnCoreValidator.requireAllowedCredential(
            response = sampleAuthenticationResponse(sampleCredentialId(1)),
            allowedCredentialIds = emptySet(),
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun requireAllowedCredentialFailsForCredentialOutsideAllowList() {
        val result = WebAuthnCoreValidator.requireAllowedCredential(
            response = sampleAuthenticationResponse(sampleCredentialId(2)),
            allowedCredentialIds = setOf(sampleCredentialId(3).value.encoded()),
        )
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun requireAllowedCredentialPassesForCredentialInAllowList() {
        val credential = sampleCredentialId(4)
        val result = WebAuthnCoreValidator.requireAllowedCredential(
            response = sampleAuthenticationResponse(credential),
            allowedCredentialIds = setOf(credential.value.encoded()),
        )
        assertTrue(result is ValidationResult.Valid)
    }

    @Test
    fun validateRegistrationFailsWhenClientDataIsInvalid() {
        val challenge = sampleChallenge(6)
        val result = WebAuthnCoreValidator.validateRegistration(
            RegistrationValidationInput(
                options = sampleCreationOptions(challenge),
                response = sampleRegistrationResponse(sampleCredentialId(5), signCount = 1),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = challenge,
                    origin = sampleOrigin(),
                ),
                expectedOrigin = sampleOrigin(),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun validateRegistrationReturnsCredentialIdAndSignCountForValidInput() {
        val challenge = sampleChallenge(7)
        val credential = sampleCredentialId(6)
        val signCount = 22L
        val result = WebAuthnCoreValidator.validateRegistration(
            RegistrationValidationInput(
                options = sampleCreationOptions(challenge),
                response = sampleRegistrationResponse(credential, signCount = signCount),
                clientData = CollectedClientData(
                    type = "webauthn.create",
                    challenge = challenge,
                    origin = sampleOrigin(),
                ),
                expectedOrigin = sampleOrigin(),
            ),
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals(credential.value.encoded(), result.value.credentialId.value.encoded())
        assertEquals(signCount, result.value.signCount)
    }

    @Test
    fun validateAuthenticationFailsWhenClientDataIsInvalid() {
        val challenge = sampleChallenge(8)
        val result = WebAuthnCoreValidator.validateAuthentication(
            AuthenticationValidationInput(
                options = sampleRequestOptions(challenge),
                response = sampleAuthenticationResponse(sampleCredentialId(7), signCount = 2),
                clientData = CollectedClientData(
                    type = "webauthn.create",
                    challenge = challenge,
                    origin = sampleOrigin(),
                ),
                expectedOrigin = sampleOrigin(),
                previousSignCount = 1,
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun validateAuthenticationReturnsCredentialIdAndSignCountForValidInput() {
        val challenge = sampleChallenge(9)
        val credential = sampleCredentialId(8)
        val signCount = 33L
        val result = WebAuthnCoreValidator.validateAuthentication(
            AuthenticationValidationInput(
                options = sampleRequestOptions(challenge),
                response = sampleAuthenticationResponse(credential, signCount = signCount),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = challenge,
                    origin = sampleOrigin(),
                ),
                expectedOrigin = sampleOrigin(),
                previousSignCount = 3,
            ),
        )

        assertTrue(result is ValidationResult.Valid)
        assertEquals(credential.value.encoded(), result.value.credentialId.value.encoded())
        assertEquals(signCount, result.value.signCount)
    }

    private fun sampleChallenge(seed: Int): Challenge = Challenge.fromBytes(ByteArray(16) { seed.toByte() })

    private fun sampleOrigin(): Origin = Origin.parseOrThrow("https://example.com")

    private fun sampleRpId(): RpId = RpId.parseOrThrow("example.com")

    private fun sampleCredentialId(seed: Int): CredentialId = CredentialId.fromBytes(ByteArray(16) { seed.toByte() })

    private fun sampleCreationOptions(challenge: Challenge): PublicKeyCredentialCreationOptions {
        return PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(id = sampleRpId(), name = "Example"),
            user = PublicKeyCredentialUserEntity(
                id = UserHandle.fromBytes(ByteArray(16) { 11 }),
                name = "alice",
                displayName = "Alice",
            ),
            challenge = challenge,
            pubKeyCredParams = listOf(
                PublicKeyCredentialParameters(
                    type = PublicKeyCredentialType.PUBLIC_KEY,
                    alg = -7,
                ),
            ),
        )
    }

    private fun sampleRequestOptions(challenge: Challenge): PublicKeyCredentialRequestOptions {
        return PublicKeyCredentialRequestOptions(
            challenge = challenge,
            rpId = sampleRpId(),
        )
    }

    private fun sampleRegistrationResponse(
        credentialId: CredentialId,
        signCount: Long,
        flags: Int = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
    ): RegistrationResponse {
        return RegistrationResponse(
            credentialId = credentialId,
            clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
            attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(4, 5, 6)),
            rawAuthenticatorData = AuthenticatorData(
                rpIdHash = ByteArray(32) { 1 },
                flags = flags,
                signCount = signCount,
            ),
            attestedCredentialData = AttestedCredentialData(
                aaguid = ByteArray(16),
                credentialId = credentialId,
                cosePublicKey = byteArrayOf(9, 8, 7),
            ),
        )
    }

    private fun sampleAuthenticationResponse(
        credentialId: CredentialId,
        signCount: Long = 1,
        flags: Int = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
    ): AuthenticationResponse {
        return AuthenticationResponse(
            credentialId = credentialId,
            clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
            authenticatorData = AuthenticatorData(
                rpIdHash = ByteArray(32) { 2 },
                flags = flags,
                signCount = signCount,
            ),
            signature = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)),
            userHandle = null,
        )
    }
}
