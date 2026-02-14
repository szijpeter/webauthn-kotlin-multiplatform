package dev.webauthn.core

import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.ValidationResult
import kotlin.test.Test
import kotlin.test.assertTrue

class WebAuthnCoreValidatorTest {
    @Test
    fun clientDataFailsForOriginMismatch() {
        val result = WebAuthnCoreValidator.validateClientData(
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = Challenge.fromBytes(ByteArray(16) { 1 }),
                origin = Origin.parseOrThrow("https://example.com"),
            ),
            expectedType = "webauthn.get",
            expectedChallenge = Challenge.fromBytes(ByteArray(16) { 1 }).value.encoded(),
            expectedOrigin = Origin.parseOrThrow("https://login.example.com"),
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
}
