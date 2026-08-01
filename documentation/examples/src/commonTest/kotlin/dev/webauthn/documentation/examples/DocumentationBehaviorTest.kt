package dev.webauthn.documentation.examples

import dev.webauthn.core.AuthenticationValidationInput
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RpId
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class DocumentationBehaviorTest {
    @Test
    fun requestOptionsExampleRejectsAnOriginInsteadOfAnRpId() {
        val result = buildSignInOptions(
            challengeBytes = ByteArray(16) { 7 },
            rpIdFromRequest = "https://example.com",
            storedCredentialId = "AQID",
        )

        assertIs<ValidationResult.Invalid>(result)
    }

    @Test
    fun requestOptionsExampleBuildsValidatedOptions() {
        val result = buildSignInOptions(
            challengeBytes = ByteArray(16) { 7 },
            rpIdFromRequest = "example.com",
            storedCredentialId = "AQID",
        )

        val options = assertIs<ValidationResult.Valid<PublicKeyCredentialRequestOptions>>(result).value
        assertEquals("example.com", options.rpId?.value)
        assertEquals(1, options.allowCredentials.size)
    }

    @Test
    fun runtimeExampleMapsOrdinaryFailures() = runTest {
        val result = loadAndTransform(
            fetchData = { error("offline") },
            transform = { it.length },
            mapFailure = { -1 },
        )

        assertEquals(-1, result)
    }

    @Test
    fun runtimeExamplePreservesCancellation() = runTest {
        assertFailsWith<CancellationException> {
            loadAndTransform(
                fetchData = { throw CancellationException("cancel") },
                transform = { it.length },
                mapFailure = { -1 },
            )
        }
    }

    @Test
    fun coreValidationExampleDoesNotReturnValidWhenSignatureVerificationFails() = runTest {
        val challenge = Challenge.fromBytes(ByteArray(16) { 9 })
        val credential = CredentialId.fromBytes(ByteArray(16) { 8 })
        val origin = Origin.parseOrThrow("https://example.com")
        val input = AuthenticationValidationInput(
            options = PublicKeyCredentialRequestOptions(
                challenge = challenge,
                rpId = RpId.parseOrThrow("example.com"),
            ),
            response = AuthenticationResponse(
                credentialId = credential,
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                rawAuthenticatorData = Base64UrlBytes.fromBytes(ByteArray(37)),
                authenticatorData = AuthenticatorData(
                    rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 2 }),
                    flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                    signCount = 33,
                ),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)),
                userHandle = null,
            ),
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = challenge,
                origin = origin,
            ),
            expectedOrigin = origin,
            previousSignCount = 3,
        )

        val result = validateAssertionForFinish(
            input = input,
            allowedCredentialIds = setOf(credential),
            verifySignature = {
                ValidationResult.Invalid(
                    listOf(
                        WebAuthnValidationError.InvalidValue(
                            field = "signature",
                            message = "signature verification failed",
                        ),
                    ),
                )
            },
        )

        assertIs<ValidationResult.Invalid>(result)
    }

    @Test
    fun coreValidationExampleReturnsSignCountOnlyAfterSignatureVerificationSucceeds() = runTest {
        val challenge = Challenge.fromBytes(ByteArray(16) { 11 })
        val credential = CredentialId.fromBytes(ByteArray(16) { 10 })
        val origin = Origin.parseOrThrow("https://example.com")
        val signCount = 44L
        val input = AuthenticationValidationInput(
            options = PublicKeyCredentialRequestOptions(
                challenge = challenge,
                rpId = RpId.parseOrThrow("example.com"),
            ),
            response = AuthenticationResponse(
                credentialId = credential,
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)),
                rawAuthenticatorData = Base64UrlBytes.fromBytes(ByteArray(37)),
                authenticatorData = AuthenticatorData(
                    rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 2 }),
                    flags = WebAuthnCoreValidator.USER_PRESENCE_FLAG,
                    signCount = signCount,
                ),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)),
                userHandle = null,
            ),
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = challenge,
                origin = origin,
            ),
            expectedOrigin = origin,
            previousSignCount = 3,
        )

        val result = validateAssertionForFinish(
            input = input,
            allowedCredentialIds = setOf(credential),
            verifySignature = { ValidationResult.Valid(Unit) },
        )

        assertEquals(signCount, assertIs<ValidationResult.Valid<Long>>(result).value)
    }
}
