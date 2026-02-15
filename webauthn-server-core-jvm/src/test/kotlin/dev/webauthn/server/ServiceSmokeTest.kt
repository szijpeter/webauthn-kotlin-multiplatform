package dev.webauthn.server

import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
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
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ServiceSmokeTest {
    @Test
    fun registrationStartIssuesChallengeAndParams() = runBlocking {
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()
        val registrationService = RegistrationService(
            challengeStore = InMemoryChallengeStore(),
            credentialStore = InMemoryCredentialStore(),
            userAccountStore = InMemoryUserAccountStore(),
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
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
    fun registrationFinishStoresCredential() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()
        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            attestationPolicy = AttestationPolicy.Strict,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
        )
        val options = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val finish = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(finish is ValidationResult.Valid)
        assertTrue(credentialStore.findById(credentialId) != null)
    }

    @Test
    fun registrationFinishCallsExtensionHooks() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        var hookCalled = false
        val hook = object : dev.webauthn.core.WebAuthnExtensionHook {
            @OptIn(dev.webauthn.model.ExperimentalWebAuthnL3Api::class)
            override fun validateRegistrationExtensions(
                inputs: dev.webauthn.model.AuthenticationExtensionsClientInputs?,
                outputs: dev.webauthn.model.AuthenticationExtensionsClientOutputs?,
            ): ValidationResult<Unit> {
                hookCalled = true
                return ValidationResult.Valid(Unit)
            }

            @OptIn(dev.webauthn.model.ExperimentalWebAuthnL3Api::class)
            override fun validateAuthenticationExtensions(
                inputs: dev.webauthn.model.AuthenticationExtensionsClientInputs?,
                outputs: dev.webauthn.model.AuthenticationExtensionsClientOutputs?,
            ): ValidationResult<Unit> = ValidationResult.Valid(Unit)
        }

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            attestationPolicy = AttestationPolicy.Strict,
            extensionHooks = listOf(hook),
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
        )
        val options = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(hookCalled)
    }

    @Test
    fun authenticationFinishUpdatesSignatureCounter() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()
        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            attestationPolicy = AttestationPolicy.Strict,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val registrationOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        val registrationResult = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = registrationOptions.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )
        assertTrue(registrationResult is ValidationResult.Valid)

        val authStart = authenticationService.start(
            AuthenticationStartRequest(
                rpId = startRequest.rpId,
                origin = startRequest.origin,
                userName = startRequest.userName,
            ),
        )
        assertTrue(authStart is ValidationResult.Valid)
        val authChallenge: Challenge = authStart.value.challenge
        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId(startRequest.rpId.value),
            flags = 0x01,
            signCount = 2,
        )
        val authFinish = authenticationService.finish(
            AuthenticationFinishRequest(
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
                    challenge = authChallenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(authFinish is ValidationResult.Valid)
        assertEquals(2, credentialStore.findById(credentialId)?.signCount)
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

    @Test
    fun registrationFinishFailsForRpIdHashMismatch() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()
        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            attestationPolicy = AttestationPolicy.Strict,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
        )
        val options = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = ByteArray(32) { 0xFF.toByte() },
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val finish = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(finish is ValidationResult.Invalid)
    }

    @Test
    fun registrationFinishFailsForExpiredChallenge() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()
        var currentTime = 1000L

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            attestationPolicy = AttestationPolicy.Strict,
            nowEpochMs = { currentTime },
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
            timeoutMs = 60_000,
        )
        val options = registrationService.start(startRequest)

        // Jump time well past the 60s timeout
        currentTime = 1000L + 120_000L

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val result = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationFinishFailsForOriginMismatch() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
        )
        val options = registrationService.start(startRequest)

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val result = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = Origin.parseOrThrow("https://evil.com"), // wrong origin
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun registrationFinishFailsForChallengeReplay() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
        )
        val options = registrationService.start(startRequest)

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val finishRequest = RegistrationFinishRequest(
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
                challenge = options.challenge,
                origin = startRequest.origin,
            ),
        )

        val first = registrationService.finish(finishRequest)
        assertTrue(first is ValidationResult.Valid)

        // Second call with same challenge should fail (consumed)
        val second = registrationService.finish(finishRequest)
        assertTrue(second is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFinishFailsForExpiredChallenge() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()
        var currentTime = 1000L

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            nowEpochMs = { currentTime },
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
            nowEpochMs = { currentTime },
        )

        // Register first
        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = regOptions.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        // Start auth
        val authStart = authenticationService.start(
            AuthenticationStartRequest(
                rpId = startRequest.rpId,
                origin = startRequest.origin,
                userName = startRequest.userName,
                timeoutMs = 60_000,
            ),
        )
        assertTrue(authStart is ValidationResult.Valid)
        val authChallenge = authStart.value.challenge

        // Expire the challenge
        currentTime = 1000L + 120_000L

        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"),
            flags = 0x01,
            signCount = 2,
        )

        val result = authenticationService.finish(
            AuthenticationFinishRequest(
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
                    challenge = authChallenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFinishFailsForOriginMismatch() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
        )

        // Register
        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41, signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.create", challenge = regOptions.challenge, origin = startRequest.origin,
                ),
            ),
        )

        // Auth start
        val authStart = authenticationService.start(
            AuthenticationStartRequest(rpId = startRequest.rpId, origin = startRequest.origin, userName = "alice"),
        )
        assertTrue(authStart is ValidationResult.Valid)

        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"), flags = 0x01, signCount = 2,
        )

        val result = authenticationService.finish(
            AuthenticationFinishRequest(
                responseDto = AuthenticationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = AuthenticationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)).encoded(),
                        authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                        signature = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)).encoded(),
                        userHandle = null,
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = authStart.value.challenge,
                    origin = Origin.parseOrThrow("https://evil.com"), // wrong origin
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFinishFailsForUnknownCredential() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
        )

        // Register with one credential
        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41, signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.create", challenge = regOptions.challenge, origin = startRequest.origin,
                ),
            ),
        )

        // Auth start
        val authStart = authenticationService.start(
            AuthenticationStartRequest(rpId = startRequest.rpId, origin = startRequest.origin, userName = "alice"),
        )
        assertTrue(authStart is ValidationResult.Valid)

        // Try to auth with a DIFFERENT (unknown) credential ID
        val unknownCredId = CredentialId.fromBytes(ByteArray(16) { 0xFF.toByte() })
        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"), flags = 0x01, signCount = 2,
        )

        val result = authenticationService.finish(
            AuthenticationFinishRequest(
                responseDto = AuthenticationResponseDto(
                    id = unknownCredId.value.encoded(), rawId = unknownCredId.value.encoded(),
                    response = AuthenticationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)).encoded(),
                        authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                        signature = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)).encoded(),
                        userHandle = null,
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = authStart.value.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFinishFailsForSignatureVerificationFailure() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> false }, // always fails
            rpIdHasher = rpIdHasher,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41, signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.create", challenge = regOptions.challenge, origin = startRequest.origin,
                ),
            ),
        )

        val authStart = authenticationService.start(
            AuthenticationStartRequest(rpId = startRequest.rpId, origin = startRequest.origin, userName = "alice"),
        )
        assertTrue(authStart is ValidationResult.Valid)

        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"), flags = 0x01, signCount = 2,
        )

        val result = authenticationService.finish(
            AuthenticationFinishRequest(
                responseDto = AuthenticationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = AuthenticationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)).encoded(),
                        authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                        signature = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)).encoded(),
                        userHandle = null,
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = authStart.value.challenge,
                    origin = startRequest.origin,
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun authenticationFinishFailsForChallengeReplay() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = Origin.parseOrThrow("https://example.com"),
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41, signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.create", challenge = regOptions.challenge, origin = startRequest.origin,
                ),
            ),
        )

        val authStart = authenticationService.start(
            AuthenticationStartRequest(rpId = startRequest.rpId, origin = startRequest.origin, userName = "alice"),
        )
        assertTrue(authStart is ValidationResult.Valid)

        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"), flags = 0x01, signCount = 2,
        )

        val authFinishRequest = AuthenticationFinishRequest(
            responseDto = AuthenticationResponseDto(
                id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                response = AuthenticationResponsePayloadDto(
                    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)).encoded(),
                    authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                    signature = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)).encoded(),
                    userHandle = null,
                ),
            ),
            clientData = CollectedClientData(
                type = "webauthn.get",
                challenge = authStart.value.challenge,
                origin = startRequest.origin,
            ),
        )

        val first = authenticationService.finish(authFinishRequest)
        assertTrue(first is ValidationResult.Valid)

        // Second call with same challenge should fail
        val second = authenticationService.finish(authFinishRequest)
        assertTrue(second is ValidationResult.Invalid)
    }

    @Test
    fun registrationFinishSucceedsWithRelatedOrigin() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val primaryOrigin = Origin.parseOrThrow("https://example.com")
        val relatedOrigin = Origin.parseOrThrow("https://app.example.com")

        val metadataProvider = object : dev.webauthn.core.OriginMetadataProvider {
            override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> {
                return if (primaryOrigin.value == "https://example.com") setOf(relatedOrigin) else emptySet()
            }
        }

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            originMetadataProvider = metadataProvider
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = primaryOrigin,
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
            extensions = dev.webauthn.model.AuthenticationExtensionsClientInputs(
                relatedOrigins = listOf(relatedOrigin.value),
            ),
        )
        val options = registrationService.start(startRequest)

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val finish = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = relatedOrigin, // different but related!
                ),
            ),
        )

        assertTrue(finish is ValidationResult.Valid, "Should be valid because of Related Origins")
    }

    @Test
    fun registrationFinishFailsWithRelatedOriginWhenNotRequested() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val primaryOrigin = Origin.parseOrThrow("https://example.com")
        val relatedOrigin = Origin.parseOrThrow("https://app.example.com")

        val metadataProvider = object : dev.webauthn.core.OriginMetadataProvider {
            override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> {
                return if (primaryOrigin.value == "https://example.com") setOf(relatedOrigin) else emptySet()
            }
        }

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
            originMetadataProvider = metadataProvider,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = primaryOrigin,
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 7 }),
        )
        val options = registrationService.start(startRequest)

        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x21 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )

        val finish = registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = options.challenge,
                    origin = relatedOrigin,
                ),
            ),
        )

        assertTrue(finish is ValidationResult.Invalid, "Should fail when Related Origins was not requested")
    }

    @Test
    fun authenticationFinishSucceedsWithRelatedOrigin() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val primaryOrigin = Origin.parseOrThrow("https://example.com")
        val relatedOrigin = Origin.parseOrThrow("https://app.example.com")

        val metadataProvider = object : dev.webauthn.core.OriginMetadataProvider {
            override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> {
                return if (primaryOrigin.value == "https://example.com") setOf(relatedOrigin) else emptySet()
            }
        }

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
            originMetadataProvider = metadataProvider
        )

        // Register
        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = primaryOrigin,
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41, signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
                responseDto = RegistrationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = RegistrationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
                        attestationObject = Base64UrlBytes.fromBytes(attestationObject).encoded(),
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.create", challenge = regOptions.challenge, origin = primaryOrigin,
                ),
            ),
        )

        // Auth start
        val authStart = authenticationService.start(
            AuthenticationStartRequest(
                rpId = startRequest.rpId,
                origin = primaryOrigin,
                userName = "alice",
                extensions = dev.webauthn.model.AuthenticationExtensionsClientInputs(
                    relatedOrigins = listOf(relatedOrigin.value),
                ),
            ),
        )
        assertTrue(authStart is ValidationResult.Valid)

        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"), flags = 0x01, signCount = 2,
        )

        val result = authenticationService.finish(
            AuthenticationFinishRequest(
                responseDto = AuthenticationResponseDto(
                    id = credentialId.value.encoded(), rawId = credentialId.value.encoded(),
                    response = AuthenticationResponsePayloadDto(
                        clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(7, 7, 7)).encoded(),
                        authenticatorData = Base64UrlBytes.fromBytes(authData).encoded(),
                        signature = Base64UrlBytes.fromBytes(byteArrayOf(1, 1, 1)).encoded(),
                        userHandle = null,
                    ),
                ),
                clientData = CollectedClientData(
                    type = "webauthn.get",
                    challenge = authStart.value.challenge,
                    origin = relatedOrigin, // different but related!
                ),
            ),
        )

        assertTrue(result is ValidationResult.Valid, "Should be valid because of Related Origins")
    }

    @Test
    fun authenticationFinishFailsWithRelatedOriginWhenNotRequested() = runBlocking {
        val challengeStore = InMemoryChallengeStore()
        val credentialStore = InMemoryCredentialStore()
        val userStore = InMemoryUserAccountStore()
        val rpIdHasher = dev.webauthn.server.crypto.JvmRpIdHasher()

        val primaryOrigin = Origin.parseOrThrow("https://example.com")
        val relatedOrigin = Origin.parseOrThrow("https://app.example.com")

        val metadataProvider = object : dev.webauthn.core.OriginMetadataProvider {
            override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> {
                return if (primaryOrigin.value == "https://example.com") setOf(relatedOrigin) else emptySet()
            }
        }

        val registrationService = RegistrationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            attestationVerifier = AttestationVerifier { ValidationResult.Valid(Unit) },
            rpIdHasher = rpIdHasher,
        )
        val authenticationService = AuthenticationService(
            challengeStore = challengeStore,
            credentialStore = credentialStore,
            userAccountStore = userStore,
            signatureVerifier = SignatureVerifier { _: CoseAlgorithm, _: ByteArray, _: ByteArray, _: ByteArray -> true },
            rpIdHasher = rpIdHasher,
            originMetadataProvider = metadataProvider,
        )

        val startRequest = RegistrationStartRequest(
            rpId = RpId.parseOrThrow("example.com"),
            rpName = "Example",
            origin = primaryOrigin,
            userName = "alice",
            userDisplayName = "Alice",
            userHandle = UserHandle.fromBytes(ByteArray(16) { 9 }),
        )
        val regOptions = registrationService.start(startRequest)
        val credentialId = CredentialId.fromBytes(ByteArray(16) { 0x31 })
        val attestationObject = attestationObjectWithAuthData(
            registrationAuthenticatorDataBytes(
                rpIdHash = rpIdHasher.hashRpId("example.com"),
                flags = 0x41,
                signCount = 1,
                credentialId = credentialId.value.bytes(),
                cosePublicKey = byteArrayOf(0xA1.toByte(), 0x01, 0x02),
            ),
        )
        registrationService.finish(
            RegistrationFinishRequest(
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
                    challenge = regOptions.challenge,
                    origin = primaryOrigin,
                ),
            ),
        )

        val authStart = authenticationService.start(
            AuthenticationStartRequest(
                rpId = startRequest.rpId,
                origin = primaryOrigin,
                userName = "alice",
            ),
        )
        assertTrue(authStart is ValidationResult.Valid)

        val authData = authenticationAuthenticatorDataBytes(
            rpIdHash = rpIdHasher.hashRpId("example.com"),
            flags = 0x01,
            signCount = 2,
        )

        val result = authenticationService.finish(
            AuthenticationFinishRequest(
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
                    challenge = authStart.value.challenge,
                    origin = relatedOrigin,
                ),
            ),
        )

        assertTrue(result is ValidationResult.Invalid, "Should fail when Related Origins was not requested")
    }

    private fun authenticationAuthenticatorDataBytes(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
    ): ByteArray {
        return concat(
            rpIdHash,
            byteArrayOf(flags.toByte()),
            uint32(signCount),
        )
    }

    private fun registrationAuthenticatorDataBytes(
        rpIdHash: ByteArray = ByteArray(32) { 0x10 },
        flags: Int,
        signCount: Long,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
    ): ByteArray {
        return concat(
            rpIdHash,
            byteArrayOf(flags.toByte()),
            uint32(signCount),
            ByteArray(16) { 0x22 },
            uint16(credentialId.size),
            credentialId,
            cosePublicKey,
        )
    }

    private fun attestationObjectWithAuthData(authData: ByteArray): ByteArray {
        return cborMap(
            "fmt" to cborText("none"),
            "authData" to cborBytes(authData),
            "attStmt" to cborMap(),
        )
    }

    private fun cborMap(vararg entries: Pair<String, ByteArray>): ByteArray {
        var result = cborHeader(majorType = 5, length = entries.size)
        entries.forEach { (key, value) ->
            result = concat(result, cborText(key), value)
        }
        return result
    }

    private fun cborText(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return concat(cborHeader(majorType = 3, length = bytes.size), bytes)
    }

    private fun cborBytes(value: ByteArray): ByteArray {
        return concat(cborHeader(majorType = 2, length = value.size), value)
    }

    private fun cborHeader(majorType: Int, length: Int): ByteArray {
        return if (length < 24) {
            byteArrayOf(((majorType shl 5) or length).toByte())
        } else {
            byteArrayOf(((majorType shl 5) or 24).toByte(), length.toByte())
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
