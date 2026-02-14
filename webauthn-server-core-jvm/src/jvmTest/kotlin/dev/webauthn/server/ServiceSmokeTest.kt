package dev.webauthn.server

import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ServiceSmokeTest {
    @Test
    fun registrationStartIssuesChallengeAndParams() = runBlocking {
        val registrationService = RegistrationService(
            challengeStore = InMemoryChallengeStore(),
            credentialStore = InMemoryCredentialStore(),
            userAccountStore = InMemoryUserAccountStore(),
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            attestationPolicy = AttestationPolicy.Strict,
        )

        val options = registrationService.start(
            RegistrationStartRequest(
                rpId = RpId.parseOrThrow("example.com"),
                rpName = "Example",
                origin = Origin.parseOrThrow("https://example.com"),
                userName = "alice",
                userDisplayName = "Alice",
                userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
            ),
        )

        assertTrue(options.challenge.value.bytes().isNotEmpty())
        assertEquals(3, options.pubKeyCredParams.size)
    }

    @Test
    fun authenticationStartFailsForUnknownUser() = runBlocking {
        val authenticationService = AuthenticationService(
            challengeStore = InMemoryChallengeStore(),
            credentialStore = InMemoryCredentialStore(),
            userAccountStore = InMemoryUserAccountStore(),
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher(),
        )

        val result = authenticationService.start(
            AuthenticationStartRequest(
                rpId = RpId.parseOrThrow("example.com"),
                origin = Origin.parseOrThrow("https://example.com"),
                userName = "missing",
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }
}
