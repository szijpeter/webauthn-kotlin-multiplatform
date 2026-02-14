package dev.webauthn.server

import dev.webauthn.core.AuthenticationValidationInput
import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Challenge
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import java.security.MessageDigest
import kotlinx.datetime.Clock

public class RegistrationService(
    private val challengeStore: ChallengeStore,
    private val credentialStore: CredentialStore,
    private val userAccountStore: UserAccountStore,
    private val attestationVerifier: AttestationVerifier,
    private val attestationPolicy: AttestationPolicy = AttestationPolicy.Strict,
    private val clock: Clock = Clock.System,
) {
    public suspend fun start(request: RegistrationStartRequest): PublicKeyCredentialCreationOptions {
        val challenge = ChallengeGenerator.generate()
        challengeStore.put(
            ChallengeSession(
                challenge = challenge,
                rpId = request.rpId,
                origin = request.origin,
                userName = request.userName,
                createdAt = now(clock),
                expiresAt = challengeExpiration(clock, request.timeoutMs),
                type = CeremonyType.REGISTRATION,
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
            pubKeyCredParams = listOf(
                PublicKeyCredentialParameters(type = PublicKeyCredentialType.PUBLIC_KEY, alg = CoseAlgorithm.ES256.code),
                PublicKeyCredentialParameters(type = PublicKeyCredentialType.PUBLIC_KEY, alg = CoseAlgorithm.RS256.code),
                PublicKeyCredentialParameters(type = PublicKeyCredentialType.PUBLIC_KEY, alg = CoseAlgorithm.EdDSA.code),
            ),
            timeoutMs = request.timeoutMs,
            excludeCredentials = existingCredentials.map(::defaultCredentialDescriptor),
            residentKey = request.residentKey,
            userVerification = request.userVerification,
        )
    }

    public suspend fun finish(
        request: RegistrationFinishRequest,
    ): ValidationResult<RegistrationResponse> {
        val parsed = parseRegistrationResponse(request)
        if (parsed is ValidationResult.Invalid) {
            return parsed
        }
        val response = (parsed as ValidationResult.Valid).value

        val session = challengeStore.consume(request.clientData.challenge, CeremonyType.REGISTRATION)
            ?: return failure("challenge", "Unknown or expired registration challenge")

        if (now(clock) > session.expiresAt) {
            return failure("challenge", "Registration challenge has expired")
        }

        if (request.clientData.origin != session.origin) {
            return failure("origin", "Origin mismatch")
        }

        val options = PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(id = session.rpId, name = session.rpId.value),
            user = PublicKeyCredentialUserEntity(
                id = UserAccountStoreLookup.findRequired(userAccountStore, session.userName).id,
                name = session.userName,
                displayName = session.userName,
            ),
            challenge = session.challenge,
            pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, CoseAlgorithm.ES256.code)),
        )

        val validation = WebAuthnCoreValidator.validateRegistration(
            RegistrationValidationInput(
                options = options,
                response = response,
                clientData = request.clientData,
                expectedOrigin = session.origin,
            ),
        )

        if (validation is ValidationResult.Invalid) {
            return validation
        }

        val attestationResult = attestationPolicy.verify(
            verifier = attestationVerifier,
            input = RegistrationValidationInput(
                options = options,
                response = response,
                clientData = request.clientData,
                expectedOrigin = session.origin,
            ),
        )

        if (attestationResult is ValidationResult.Invalid) {
            return attestationResult
        }

        credentialStore.save(storedCredentialFromAttestedData(response, request = RegistrationStartRequest(
            rpId = session.rpId,
            rpName = session.rpId.value,
            origin = session.origin,
            userName = session.userName,
            userDisplayName = session.userName,
            userHandle = UserAccountStoreLookup.findRequired(userAccountStore, session.userName).id,
        )))

        return ValidationResult.Valid(response)
    }
}

public class AuthenticationService(
    private val challengeStore: ChallengeStore,
    private val credentialStore: CredentialStore,
    private val userAccountStore: UserAccountStore,
    private val signatureVerifier: SignatureVerifier,
    private val rpIdHasher: RpIdHasher,
    private val clock: Clock = Clock.System,
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
                createdAt = now(clock),
                expiresAt = challengeExpiration(clock, request.timeoutMs),
                type = CeremonyType.AUTHENTICATION,
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
            ),
        )
    }

    public suspend fun finish(request: AuthenticationFinishRequest): ValidationResult<AuthenticationResponse> {
        val parsed = parseAuthenticationResponse(request)
        if (parsed is ValidationResult.Invalid) {
            return parsed
        }
        val response = (parsed as ValidationResult.Valid).value

        val session = challengeStore.consume(request.clientData.challenge, CeremonyType.AUTHENTICATION)
            ?: return failure("challenge", "Unknown or expired authentication challenge")

        if (now(clock) > session.expiresAt) {
            return failure("challenge", "Authentication challenge has expired")
        }

        if (request.clientData.origin != session.origin) {
            return failure("origin", "Origin mismatch")
        }

        val storedCredential = credentialStore.findById(response.credentialId)
            ?: return failure("credentialId", "Unknown credential")

        val requestOptions = PublicKeyCredentialRequestOptions(
            challenge = session.challenge,
            rpId = session.rpId,
            allowCredentials = listOf(defaultCredentialDescriptor(storedCredential)),
        )

        val validation = WebAuthnCoreValidator.validateAuthentication(
            AuthenticationValidationInput(
                options = requestOptions,
                response = response,
                clientData = request.clientData,
                expectedOrigin = session.origin,
                previousSignCount = storedCredential.signCount,
            ),
        )

        if (validation is ValidationResult.Invalid) {
            return validation
        }

        val rpHashExpected = rpIdHasher.hashRpId(session.rpId.value)
        if (!response.authenticatorData.rpIdHash.contentEquals(rpHashExpected)) {
            return failure("authenticatorData.rpIdHash", "rpId hash does not match")
        }

        val signedData = signedAuthenticationData(response)
        val signatureOk = signatureVerifier.verify(
            algorithm = CoseAlgorithm.ES256,
            publicKeyCose = storedCredential.publicKeyCose,
            data = signedData,
            signature = response.signature.bytes(),
        )

        if (!signatureOk) {
            return failure("signature", "Invalid assertion signature")
        }

        credentialStore.updateSignCount(response.credentialId, response.authenticatorData.signCount)

        return ValidationResult.Valid(response)
    }

    private fun signedAuthenticationData(response: AuthenticationResponse): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val clientDataHash = digest.digest(response.clientDataJson.bytes())
        val rawAuthData = response.authenticatorData.rpIdHash +
            byteArrayOf(response.authenticatorData.flags.toByte()) +
            response.authenticatorData.signCount.toInt().toByteArray()
        return rawAuthData + clientDataHash
    }
}

private object UserAccountStoreLookup {
    suspend fun findRequired(store: UserAccountStore, name: String): UserAccount {
        return requireNotNull(store.findByName(name)) { "User not found in account store: $name" }
    }
}

private fun Int.toByteArray(): ByteArray {
    return byteArrayOf(
        ((this shr 24) and 0xFF).toByte(),
        ((this shr 16) and 0xFF).toByte(),
        ((this shr 8) and 0xFF).toByte(),
        (this and 0xFF).toByte(),
    )
}
