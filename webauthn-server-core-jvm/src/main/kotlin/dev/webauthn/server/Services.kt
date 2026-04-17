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
import dev.webauthn.model.PublicKeyCredentialDescriptor
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

        val sessionUser = when (val result = resolveRegistrationSessionUser(session, userAccountStore)) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> return result
        }
        val options = registrationOptionsFor(session, sessionUser.userHandle, sessionUser.userName)

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
                    userName = sessionUser.userName,
                    userDisplayName = sessionUser.userName,
                    userHandle = sessionUser.userHandle,
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
        val user = request.userName?.let { userName ->
            userAccountStore.findByName(userName)
                ?: return failure("userName", "Unknown user")
        }

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

        val credentials = user?.let { credentialStore.findByUserId(it.id) }.orEmpty()

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

        val credentialContext = when (
            val result = resolveAuthenticationCredentialContext(
                session = session,
                response = response,
                credentialStore = credentialStore,
                userAccountStore = userAccountStore,
            )
        ) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> return result
        }
        val storedCredential = credentialContext.storedCredential
        val allowCredentials = credentialContext.allowCredentials

        val requestOptions = authenticationOptionsFor(session, allowCredentials)
        val allowedCredentialResult = WebAuthnCoreValidator.requireAllowedCredential(
            response = response,
            allowedCredentialIds = allowCredentials.map { it.id }.toSet(),
        )
        if (allowedCredentialResult is ValidationResult.Invalid) {
            return allowedCredentialResult
        }

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
        val signedData = buildSignedAuthenticationData(response)
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

        when (val extensionResult = validateAuthenticationExtensionHooks(extensionHooks, requestOptions, response)) {
            is ValidationResult.Valid -> Unit
            is ValidationResult.Invalid -> return extensionResult
        }

        return ValidationResult.Valid(response)
    }
}

internal fun buildSignedAuthenticationData(response: AuthenticationResponse): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    val clientDataHash = digest.digest(response.clientDataJson.bytes())
    return response.rawAuthenticatorData.bytes() + clientDataHash
}

private fun registrationOptionsFor(
    session: ChallengeSession,
    userHandle: UserHandle,
    userName: String,
): PublicKeyCredentialCreationOptions {
    return PublicKeyCredentialCreationOptions(
        rp = PublicKeyCredentialRpEntity(id = session.rpId, name = session.rpId.value),
        user = PublicKeyCredentialUserEntity(
            id = userHandle,
            name = userName,
            displayName = userName,
        ),
        challenge = session.challenge,
        pubKeyCredParams = supportedCredentialParameters(),
        extensions = session.extensions,
    )
}

private fun authenticationOptionsFor(
    session: ChallengeSession,
    allowCredentials: List<PublicKeyCredentialDescriptor>,
): PublicKeyCredentialRequestOptions {
    return PublicKeyCredentialRequestOptions(
        challenge = session.challenge,
        rpId = session.rpId,
        allowCredentials = allowCredentials,
        extensions = session.extensions,
    )
}

private data class RegistrationSessionUser(
    val userName: String,
    val userHandle: UserHandle,
)

private suspend fun resolveRegistrationSessionUser(
    session: ChallengeSession,
    userAccountStore: UserAccountStore,
): ValidationResult<RegistrationSessionUser> {
    val userName = session.userName ?: return failure("userName", "Unknown user")
    val userHandle = userAccountStore.findByName(userName)?.id ?: return failure("userName", "Unknown user")
    return ValidationResult.Valid(RegistrationSessionUser(userName = userName, userHandle = userHandle))
}

private data class AuthenticationCredentialContext(
    val storedCredential: StoredCredential,
    val allowCredentials: List<PublicKeyCredentialDescriptor>,
)

private suspend fun resolveAuthenticationCredentialContext(
    session: ChallengeSession,
    response: AuthenticationResponse,
    credentialStore: CredentialStore,
    userAccountStore: UserAccountStore,
): ValidationResult<AuthenticationCredentialContext> {
    val storedCredential = credentialStore.findById(response.credentialId)
        ?: return failure("credentialId", "Unknown credential")
    if (storedCredential.rpId != session.rpId) {
        return failure("credentialId", "Credential rpId does not match ceremony rpId")
    }

    val userName = session.userName
    val allowCredentials = if (userName == null) {
        emptyList()
    } else {
        val user = userAccountStore.findByName(userName)
            ?: return failure("userName", "Unknown user")
        if (storedCredential.userId != user.id) {
            return failure("credentialId", "Credential does not belong to authenticated user")
        }
        credentialStore.findByUserId(user.id).map(::defaultCredentialDescriptor)
    }

    return ValidationResult.Valid(
        AuthenticationCredentialContext(
            storedCredential = storedCredential,
            allowCredentials = allowCredentials,
        ),
    )
}

@OptIn(ExperimentalWebAuthnL3Api::class)
private fun validateAuthenticationExtensionHooks(
    extensionHooks: List<WebAuthnExtensionHook>,
    requestOptions: PublicKeyCredentialRequestOptions,
    response: AuthenticationResponse,
): ValidationResult<Unit> {
    for (hook in extensionHooks) {
        val hookResult = hook.validateAuthenticationExtensions(requestOptions.extensions, response.extensions)
        if (hookResult is ValidationResult.Invalid) {
            return hookResult
        }
    }
    return ValidationResult.Valid(Unit)
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
