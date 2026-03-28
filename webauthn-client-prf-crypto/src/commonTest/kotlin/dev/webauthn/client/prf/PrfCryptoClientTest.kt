package dev.webauthn.client.prf

import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.RpIdHash
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

@OptIn(ExperimentalWebAuthnL3Api::class)
class PrfCryptoClientTest {
    @Test
    fun deriveAes256Key_isDeterministic_forSameInputs() = runTest {
        val prfOutput = bytes(1, 2, 3, 4, 5, 6, 7, 8)

        val a = PrfCrypto.deriveAes256Key(prfOutput, context = "ctx")
        val b = PrfCrypto.deriveAes256Key(prfOutput, context = "ctx")

        assertEquals(a.encoded(), b.encoded())
    }

    @Test
    fun deriveAes256Key_changes_whenContextOrSaltChanges() = runTest {
        val prfOutput = bytes(9, 8, 7, 6, 5, 4, 3, 2)
        val hkdfSalt = Base64UrlBytes.fromBytes(ByteArray(32) { 3 })

        val base = PrfCrypto.deriveAes256Key(prfOutput, context = "ctx")
        val changedContext = PrfCrypto.deriveAes256Key(prfOutput, context = "ctx-2")
        val changedSalt = PrfCrypto.deriveAes256Key(prfOutput, context = "ctx", hkdfSalt = hkdfSalt)

        assertNotEquals(base.encoded(), changedContext.encoded())
        assertNotEquals(base.encoded(), changedSalt.encoded())
    }

    @Test
    fun aesGcm_roundtrip_encryptDecrypt_succeeds() = runTest {
        val key = PrfCrypto.deriveAes256Key(bytes(1, 1, 1, 1), context = "roundtrip")
        val plaintext = Base64UrlBytes.fromBytes("hello-prf".encodeToByteArray())
        val aad = Base64UrlBytes.fromBytes("aad".encodeToByteArray())

        val encrypted = PrfCrypto.encryptAesGcm(key, plaintext, aad)
        val decrypted = PrfCrypto.decryptAesGcm(key, encrypted)

        assertContentEquals(plaintext.bytes(), decrypted.bytes())
    }

    @Test
    fun aesGcm_wrongKeyOrNonce_failsToDecrypt() = runTest {
        val key = PrfCrypto.deriveAes256Key(bytes(4, 4, 4, 4), context = "cipher")
        val otherKey = PrfCrypto.deriveAes256Key(bytes(5, 5, 5, 5), context = "cipher")
        val plaintext = Base64UrlBytes.fromBytes("secret".encodeToByteArray())

        val encrypted = PrfCrypto.encryptAesGcm(key, plaintext)

        runCatching { PrfCrypto.decryptAesGcm(otherKey, encrypted) }
            .onSuccess { fail("Decrypt should fail with wrong key") }

        val tamperedNonce = encrypted.copy(
            nonce = Base64UrlBytes.fromBytes(encrypted.nonce.bytes().also { it[0] = (it[0] + 1).toByte() }),
        )
        runCatching { PrfCrypto.decryptAesGcm(key, tamperedNonce) }
            .onSuccess { fail("Decrypt should fail with tampered nonce") }
    }

    @Test
    fun session_clear_preventsFurtherUse() = runTest {
        val session = PrfCrypto.createSession(
            prfResults = AuthenticationExtensionsPRFValues(first = bytes(3, 3, 3, 3)),
            context = "session-clear",
        )

        session.clear()
        assertTrue(session.isCleared)

        runCatching { session.encryptString("hello") }
            .onSuccess { fail("Encrypt should fail after clear()") }
    }

    @Test
    fun createSession_withSecondSelection_throwsTypedError_whenSecondMissing() = runTest {
        runCatching {
            PrfCrypto.createSession(
                prfResults = AuthenticationExtensionsPRFValues(first = bytes(3, 3, 3, 3)),
                outputSelection = PrfOutputSelection.SECOND,
                context = "missing-second",
            )
        }.onSuccess {
            fail("Expected MissingPrfOutputException when SECOND output is absent")
        }.onFailure { error ->
            assertIs<MissingPrfOutputException>(error)
        }
    }

    @Test
    fun requirePrfResults_throws_whenMissing() {
        val response = validAuthenticationResponse(extensions = null)

        runCatching { PrfCrypto.requirePrfResults(response) }
            .onSuccess { fail("Expected missing PRF results failure") }
            .onFailure { error ->
                assertTrue(error is IllegalArgumentException || error is IllegalStateException)
            }
    }

    @Test
    fun withPrfEvaluation_clearsEvalByCredential() {
        val existingOptions = validRequestOptions().copy(
            extensions = AuthenticationExtensionsClientInputs(
                prf = PrfExtensionInput(
                    evalByCredential = mapOf(
                        "cred-1" to AuthenticationExtensionsPRFValues(first = bytes(7, 7, 7, 7)),
                    ),
                ),
            ),
        )
        val evaluation = AuthenticationExtensionsPRFValues(first = bytes(1, 2, 3, 4))

        val updated = PrfCrypto.withPrfEvaluation(existingOptions, evaluation)

        assertEquals(evaluation, updated.extensions?.prf?.eval)
        assertNull(updated.extensions?.prf?.evalByCredential)
    }

    @Test
    fun authenticateWithPrf_returnsSessionAndResponse() = runTest {
        val response = validAuthenticationResponse(
            extensions = AuthenticationExtensionsClientOutputs(
                prf = PrfExtensionOutput(
                    results = AuthenticationExtensionsPRFValues(first = bytes(9, 9, 9, 9)),
                ),
            ),
        )
        val client = PrfCryptoClient(FakePasskeyClient(PasskeyResult.Success(response)))

        val result = client.authenticateWithPrf(
            options = validRequestOptions(),
            salts = AuthenticationExtensionsPRFValues(first = bytes(1, 2, 3, 4)),
        )

        val success = assertIs<PasskeyResult.Success<PrfAuthenticationResult>>(result)
        assertEquals(response.credentialId, success.value.response.credentialId)
        val ciphertext = success.value.session.encryptString("plaintext")
        val decrypted = success.value.session.decryptToString(ciphertext)
        assertEquals("plaintext", decrypted)
    }

    @Test
    fun authenticateWithPrf_mapsMissingPrfOutput_toInvalidOptions() = runTest {
        val response = validAuthenticationResponse(extensions = AuthenticationExtensionsClientOutputs(prf = null))
        val client = PrfCryptoClient(FakePasskeyClient(PasskeyResult.Success(response)))

        val result = client.authenticateWithPrf(
            options = validRequestOptions(),
            salts = AuthenticationExtensionsPRFValues(first = bytes(1, 1, 1, 1)),
        )

        val failure = assertIs<PasskeyResult.Failure>(result)
        assertIs<PasskeyClientError.InvalidOptions>(failure.error)
    }

    @Test
    fun authenticateWithPrf_mapsMissingSelectedSecondOutput_toInvalidOptions() = runTest {
        val response = validAuthenticationResponse(
            extensions = AuthenticationExtensionsClientOutputs(
                prf = PrfExtensionOutput(
                    results = AuthenticationExtensionsPRFValues(first = bytes(9, 9, 9, 9)),
                ),
            ),
        )
        val client = PrfCryptoClient(FakePasskeyClient(PasskeyResult.Success(response)))

        val result = client.authenticateWithPrf(
            options = validRequestOptions(),
            salts = AuthenticationExtensionsPRFValues(first = bytes(1, 1, 1, 1)),
            outputSelection = PrfOutputSelection.SECOND,
        )

        val failure = assertIs<PasskeyResult.Failure>(result)
        assertIs<PasskeyClientError.InvalidOptions>(failure.error)
        assertTrue(failure.error.message.contains("SECOND"))
    }

    @Test
    fun authenticateWithPrf_mapsThrownGetAssertion_toFailure() = runTest {
        val client = PrfCryptoClient(ThrowingPasskeyClient(IllegalStateException("platform boom")))

        val result = client.authenticateWithPrf(
            options = validRequestOptions(),
            salts = AuthenticationExtensionsPRFValues(first = bytes(1, 2, 3, 4)),
        )

        val failure = assertIs<PasskeyResult.Failure>(result)
        assertIs<PasskeyClientError.Platform>(failure.error)
        assertEquals("platform boom", failure.error.message)
    }

    @Test
    fun authenticateWithPrf_rethrowsCancellation() = runTest {
        val client = PrfCryptoClient(ThrowingPasskeyClient(CancellationException("cancelled")))

        assertFailsWith<CancellationException> {
            client.authenticateWithPrf(
                options = validRequestOptions(),
                salts = AuthenticationExtensionsPRFValues(first = bytes(1, 2, 3, 4)),
            )
        }
    }

    private class FakePasskeyClient(
        private val assertionResult: PasskeyResult<AuthenticationResponse>,
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
            error("unused in test")
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
            return assertionResult
        }
    }

    private class ThrowingPasskeyClient(
        private val throwable: Throwable,
    ) : PasskeyClient {
        override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
            error("unused in test")
        }

        override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
            throw throwable
        }
    }

    private companion object {
        fun validRequestOptions(): PublicKeyCredentialRequestOptions {
            return PublicKeyCredentialRequestOptions(
                challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
                rpId = RpId.parseOrThrow("example.com"),
            )
        }

        fun validAuthenticationResponse(
            extensions: AuthenticationExtensionsClientOutputs?,
        ): AuthenticationResponse {
            return AuthenticationResponse(
                credentialId = CredentialId.fromBytes(byteArrayOf(8, 8, 8)),
                clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)),
                rawAuthenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 3 }),
                authenticatorData = AuthenticatorData(
                    rpIdHash = RpIdHash.fromBytes(ByteArray(32) { 4 }),
                    flags = 0x01,
                    signCount = 2,
                ),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(5, 5, 5)),
                extensions = extensions,
            )
        }

        fun bytes(vararg value: Int): Base64UrlBytes =
            Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })
    }
}
