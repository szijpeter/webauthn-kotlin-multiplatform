package dev.webauthn.server

import dev.webauthn.core.AuthenticationValidationInput
import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.core.NoOpOriginMetadataProvider
import dev.webauthn.core.OriginMetadataProvider
import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.core.UserVerificationPolicy
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.core.WebAuthnExtensionHook
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.Origin
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import java.security.MessageDigest

/** Server registration ceremony service (WebAuthn L3 §7.1). */
public class RegistrationService(
    private val challengeStore: ChallengeStore,
    private val credentialStore: CredentialStore,
    private val userAccountStore: UserAccountStore,
    private val attestationVerifier: AttestationVerifier,
    private val rpIdHasher: RpIdHasher,
    private val attestationPolicy: AttestationPolicy = AttestationPolicy.Strict,
    @OptIn(ExperimentalWebAuthnL3Api::class)
    private val extensionHooks: List<WebAuthnExtensionHook> = emptyList(),
    private val originMetadataProvider: OriginMetadataProvider =
        NoOpOriginMetadataProvider,
    private val nowEpochMs: () -> Long = { System.currentTimeMillis() },
) {
    public suspend fun start(request: RegistrationStartRequest): PublicKeyCredentialCreationOptions {
        val challenge = ChallengeGenerator.generate()
        challengeStore.put(
            ChallengeSession(
                challenge = challenge,
                rpId = request.rpId,
                origin = request.origin,
                userName = request.userName,
                createdAtEpochMs = currentEpochMs(nowEpochMs),
                expiresAtEpochMs = challengeExpirationEpochMs(nowEpochMs, request.timeoutMs),
                type = CeremonyType.REGISTRATION,
                extensions = request.extensions,
                userVerification = request.userVerification,
            ),
        )

        userAccountStore.save(
            UserAccount(
                id = request.userHandle,
                name = request.userName,
                displayName = request.userDisplayName,
            ),
        )

        val existingCredentials = credentialStore.findByUserId(request.userHandle)

        return PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(id = request.rpId, name = request.rpName),
            user = PublicKeyCredentialUserEntity(
                id = request.userHandle,
                name = request.userName,
                displayName = request.userDisplayName,
            ),
            challenge = challenge,
            pubKeyCredParams = supportedCredentialParameters(),
            timeoutMs = request.timeoutMs,
            excludeCredentials = existingCredentials.map(::defaultCredentialDescriptor),
            residentKey = request.residentKey,
            userVerification = request.userVerification,
            extensions = request.extensions,
        )
    }

    /**
     * W3C WebAuthn L3: §7.1. Registering a New Credential
     */
    @Suppress("LongMethod")
    public suspend fun finish(request: RegistrationFinishRequest): ValidationResult<RegistrationResponse> {
        val parsed = parseRegistrationResponse(request)
        if (parsed is ValidationResult.Invalid) {
            return parsed
        }
        val response = (parsed as ValidationResult.Valid).value

        val session = challengeStore.consume(request.clientData.challenge, CeremonyType.REGISTRATION)
            ?: return failure("challenge", "Unknown or expired registration challenge")

        if (currentEpochMs(nowEpochMs) > session.expiresAtEpochMs) {
            return failure("challenge", "Registration challenge has expired")
        }

        val allowedOrigins = when (
            val result = resolveAllowedOrigins(session, request.clientData.origin, originMetadataProvider)
        ) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> return result
        }

        val userHandle = UserAccountStoreLookup.findRequired(userAccountStore, session.userName).id
        val options = registrationOptionsFor(session, userHandle)

        val validation = WebAuthnCoreValidator.validateRegistration(
            RegistrationValidationInput(
                options = options,
                response = response,
                clientData = request.clientData,
                expectedOrigin = session.origin,
                allowedOrigins = allowedOrigins,
                userVerificationPolicy = session.userVerification.toPolicy(),
            ),
        )

        if (validation is ValidationResult.Invalid) {
            return validation
        }

        val rpHashExpected = rpIdHasher.hashRpId(session.rpId.value)
        // W3C WebAuthn L3: §7.1 Step 14: Verify that authData.rpIdHash is the
        // SHA-256 hash of the expected RP ID.
        if (response.rawAuthenticatorData.rpIdHash != rpHashExpected) {
            return failure("authenticatorData.rpIdHash", "rpId hash does not match")
        }

        val attestationResult = attestationPolicy.verify(
            verifier = attestationVerifier,
            input = RegistrationValidationInput(
                options = options,
                response = response,
                clientData = request.clientData,
                expectedOrigin = session.origin,
                allowedOrigins = allowedOrigins,
            ),
        )

        if (attestationResult is ValidationResult.Invalid) {
            return attestationResult
        }

        @OptIn(ExperimentalWebAuthnL3Api::class)
        for (hook in extensionHooks) {
            val hookResult = hook.validateRegistrationExtensions(options.extensions, response.extensions)
            if (hookResult is ValidationResult.Invalid) {
                return hookResult
            }
        }

        credentialStore.save(
            storedCredentialFromAttestedData(
                response,
                request = RegistrationStartRequest(
                    rpId = session.rpId,
                    rpName = session.rpId.value,
                    origin = session.origin,
                    userName = session.userName,
                    userDisplayName = session.userName,
                    userHandle = userHandle,
                ),
            ),
        )

        return ValidationResult.Valid(response)
    }
}

/** Server authentication ceremony service (WebAuthn L3 §7.2). */
public class AuthenticationService(
    private val challengeStore: ChallengeStore,
    private val credentialStore: CredentialStore,
    private val userAccountStore: UserAccountStore,
    private val signatureVerifier: SignatureVerifier,
    private val rpIdHasher: RpIdHasher,
    @OptIn(ExperimentalWebAuthnL3Api::class)
    private val extensionHooks: List<WebAuthnExtensionHook> = emptyList(),
    private val originMetadataProvider: OriginMetadataProvider =
        NoOpOriginMetadataProvider,
    private val nowEpochMs: () -> Long = { System.currentTimeMillis() },
) {
    public suspend fun start(request: AuthenticationStartRequest): ValidationResult<PublicKeyCredentialRequestOptions> {
        val user = userAccountStore.findByName(request.userName)
            ?: return failure("userName", "Unknown user")

        val challenge = ChallengeGenerator.generate()
        challengeStore.put(
            ChallengeSession(
                challenge = challenge,
                rpId = request.rpId,
                origin = request.origin,
                userName = request.userName,
                createdAtEpochMs = currentEpochMs(nowEpochMs),
                expiresAtEpochMs = challengeExpirationEpochMs(nowEpochMs, request.timeoutMs),
                type = CeremonyType.AUTHENTICATION,
                extensions = request.extensions,
                userVerification = request.userVerification,
            ),
        )

        val credentials = credentialStore.findByUserId(user.id)

        return ValidationResult.Valid(
            PublicKeyCredentialRequestOptions(
                challenge = challenge,
                rpId = request.rpId,
                timeoutMs = request.timeoutMs,
                allowCredentials = credentials.map(::defaultCredentialDescriptor),
                userVerification = request.userVerification,
                extensions = request.extensions,
            ),
        )
    }

    /**
     * W3C WebAuthn L3: §7.2. Verifying an Authentication Assertion
     */
    // Spec-step validation is intentionally structured as fail-fast guards for auditability.
    @Suppress("LongMethod", "ReturnCount")
    public suspend fun finish(request: AuthenticationFinishRequest): ValidationResult<AuthenticationResponse> {
        val parsed = parseAuthenticationResponse(request)
        if (parsed is ValidationResult.Invalid) {
            return parsed
        }
        val response = (parsed as ValidationResult.Valid).value

        val session = challengeStore.consume(request.clientData.challenge, CeremonyType.AUTHENTICATION)
            ?: return failure("challenge", "Unknown or expired authentication challenge")

        if (currentEpochMs(nowEpochMs) > session.expiresAtEpochMs) {
            return failure("challenge", "Authentication challenge has expired")
        }

        val allowedOrigins = when (
            val result = resolveAllowedOrigins(session, request.clientData.origin, originMetadataProvider)
        ) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> return result
        }

        val storedCredential = credentialStore.findById(response.credentialId)
            ?: return failure("credentialId", "Unknown credential")

        val requestOptions = authenticationOptionsFor(session, storedCredential)

        val validation = WebAuthnCoreValidator.validateAuthentication(
            AuthenticationValidationInput(
                options = requestOptions,
                response = response,
                clientData = request.clientData,
                expectedOrigin = session.origin,
                allowedOrigins = allowedOrigins,
                previousSignCount = storedCredential.signCount,
                userVerificationPolicy = session.userVerification.toPolicy(),
            ),
        )

        if (validation is ValidationResult.Invalid) {
            return validation
        }

        val rpHashExpected = rpIdHasher.hashRpId(session.rpId.value)
        // W3C WebAuthn L3: §7.2 Step 19: Verify that authData.rpIdHash is the
        // SHA-256 hash of the expected RP ID.
        if (response.authenticatorData.rpIdHash != rpHashExpected) {
            return failure("authenticatorData.rpIdHash", "rpId hash does not match")
        }

        // W3C WebAuthn L3: §7.2 Step 23: Verify that sig is a valid signature
        // over the binary concatenation of authData and hash.
        val signedData = signedAuthenticationData(response)
        val signatureOk = CoseAlgorithm.entries.any { algorithm ->
            signatureVerifier.verify(
                algorithm = algorithm,
                publicKeyCose = storedCredential.publicKeyCose,
                data = signedData,
                signature = response.signature.bytes(),
            )
        }

        if (!signatureOk) {
            return failure("signature", "Invalid assertion signature")
        }

        credentialStore.updateSignCount(response.credentialId, response.authenticatorData.signCount)

        @OptIn(ExperimentalWebAuthnL3Api::class)
        for (hook in extensionHooks) {
            val hookResult = hook.validateAuthenticationExtensions(requestOptions.extensions, response.extensions)
            if (hookResult is ValidationResult.Invalid) {
                return hookResult
            }
        }

        return ValidationResult.Valid(response)
    }

    private fun signedAuthenticationData(response: AuthenticationResponse): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val clientDataHash = digest.digest(response.clientDataJson.bytes())
        return response.rawAuthenticatorData.bytes() + clientDataHash
    }
}

private object UserAccountStoreLookup {
    suspend fun findRequired(store: UserAccountStore, name: String): UserAccount {
        return requireNotNull(store.findByName(name)) { "User not found in account store: $name" }
    }
}

private fun registrationOptionsFor(
    session: ChallengeSession,
    userHandle: UserHandle,
): PublicKeyCredentialCreationOptions {
    return PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(id = session.rpId, name = session.rpId.value),
        user = PublicKeyCredentialUserEntity(
            id = userHandle,
            name = session.userName,
            displayName = session.userName,
        ),
        challenge = session.challenge,
        pubKeyCredParams = supportedCredentialParameters(),
        extensions = session.extensions,
    )
}

private fun authenticationOptionsFor(
    session: ChallengeSession,
    storedCredential: StoredCredential,
): PublicKeyCredentialRequestOptions {
    return PublicKeyCredentialRequestOptions(
        challenge = session.challenge,
        rpId = session.rpId,
        allowCredentials = listOf(defaultCredentialDescriptor(storedCredential)),
        extensions = session.extensions,
    )
}

private fun supportedCredentialParameters(): List<PublicKeyCredentialParameters> {
    return listOf(
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, CoseAlgorithm.ES256.code),
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, CoseAlgorithm.RS256.code),
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, CoseAlgorithm.EdDSA.code),
    )
}

private suspend fun resolveAllowedOrigins(
    session: ChallengeSession,
    actualOrigin: Origin,
    originMetadataProvider: OriginMetadataProvider,
): ValidationResult<Set<Origin>> {
    if (actualOrigin == session.origin) {
        return ValidationResult.Valid(emptySet())
    }
    if (session.extensions?.relatedOrigins == null) {
        return failure("origin", "Origin mismatch")
    }

    val allowedOrigins = originMetadataProvider.getRelatedOrigins(session.origin)
    return if (allowedOrigins.contains(actualOrigin)) {
        ValidationResult.Valid(allowedOrigins)
    } else {
        failure("origin", "Origin mismatch")
    }
}

private fun UserVerificationRequirement?.toPolicy(): UserVerificationPolicy {
    return when (this) {
        UserVerificationRequirement.REQUIRED ->
            UserVerificationPolicy.REQUIRED

        UserVerificationRequirement.PREFERRED ->
            UserVerificationPolicy.PREFERRED

        UserVerificationRequirement.DISCOURAGED ->
            UserVerificationPolicy.DISCOURAGED

        null -> UserVerificationPolicy.PREFERRED
    }
}
