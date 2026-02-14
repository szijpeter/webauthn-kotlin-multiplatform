package dev.webauthn.server

import dev.webauthn.core.ChallengeSession
import dev.webauthn.core.CeremonyType
import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ResidentKeyRequirement
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import dev.webauthn.serialization.WebAuthnDtoMapper
import java.security.SecureRandom

public data class UserAccount(
    public val id: UserHandle,
    public val name: String,
    public val displayName: String,
)

public data class StoredCredential(
    public val credentialId: CredentialId,
    public val userId: UserHandle,
    public val rpId: RpId,
    public val publicKeyCose: ByteArray,
    public val signCount: Long,
)

public interface ChallengeStore {
    public suspend fun put(session: ChallengeSession)

    public suspend fun consume(challenge: Challenge, type: CeremonyType): ChallengeSession?
}

public interface CredentialStore {
    public suspend fun save(credential: StoredCredential)

    public suspend fun findById(id: CredentialId): StoredCredential?

    public suspend fun findByUserId(userId: UserHandle): List<StoredCredential>

    public suspend fun updateSignCount(id: CredentialId, signCount: Long)
}

public interface UserAccountStore {
    public suspend fun findByName(name: String): UserAccount?

    public suspend fun save(user: UserAccount)
}

public data class RegistrationStartRequest(
    public val rpId: RpId,
    public val rpName: String,
    public val origin: Origin,
    public val userName: String,
    public val userDisplayName: String,
    public val userHandle: UserHandle,
    public val timeoutMs: Long = 60_000,
    public val residentKey: ResidentKeyRequirement = ResidentKeyRequirement.PREFERRED,
    public val userVerification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
)

public data class RegistrationFinishRequest(
    public val responseDto: dev.webauthn.serialization.RegistrationResponseDto,
    public val clientData: dev.webauthn.model.CollectedClientData,
)

public data class AuthenticationStartRequest(
    public val rpId: RpId,
    public val origin: Origin,
    public val userName: String,
    public val timeoutMs: Long = 60_000,
    public val userVerification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
)

public data class AuthenticationFinishRequest(
    public val responseDto: dev.webauthn.serialization.AuthenticationResponseDto,
    public val clientData: dev.webauthn.model.CollectedClientData,
)

public sealed interface AttestationPolicy {
    public suspend fun verify(
        verifier: AttestationVerifier,
        input: RegistrationValidationInput,
    ): ValidationResult<Unit>

    public data object Strict : AttestationPolicy {
        override suspend fun verify(
            verifier: AttestationVerifier,
            input: RegistrationValidationInput,
        ): ValidationResult<Unit> = verifier.verify(input)
    }

    public data object None : AttestationPolicy {
        override suspend fun verify(
            verifier: AttestationVerifier,
            input: RegistrationValidationInput,
        ): ValidationResult<Unit> = ValidationResult.Valid(Unit)
    }
}

internal object ChallengeGenerator {
    private val random: SecureRandom = SecureRandom()

    fun generate(size: Int = 32): Challenge {
        val value = ByteArray(size)
        random.nextBytes(value)
        return Challenge.fromBytes(value)
    }
}

internal fun currentEpochMs(clock: () -> Long): Long = clock()

internal fun challengeExpirationEpochMs(clock: () -> Long, timeoutMs: Long): Long {
    return currentEpochMs(clock) + timeoutMs
}

internal fun failure(field: String, message: String): ValidationResult.Invalid {
    return ValidationResult.Invalid(
        listOf(
            WebAuthnValidationError.InvalidValue(field = field, message = message),
        ),
    )
}

internal fun parseRegistrationResponse(
    request: RegistrationFinishRequest,
): ValidationResult<RegistrationResponse> = WebAuthnDtoMapper.toModel(request.responseDto)

internal fun parseAuthenticationResponse(
    request: AuthenticationFinishRequest,
): ValidationResult<AuthenticationResponse> = WebAuthnDtoMapper.toModel(request.responseDto)

internal fun defaultCredentialDescriptor(credential: StoredCredential): dev.webauthn.model.PublicKeyCredentialDescriptor {
    return dev.webauthn.model.PublicKeyCredentialDescriptor(
        type = PublicKeyCredentialType.PUBLIC_KEY,
        id = credential.credentialId,
    )
}

internal fun storedCredentialFromAttestedData(
    response: RegistrationResponse,
    request: RegistrationStartRequest,
): StoredCredential {
    val attested: AttestedCredentialData = response.attestedCredentialData
    return StoredCredential(
        credentialId = attested.credentialId,
        userId = request.userHandle,
        rpId = request.rpId,
        publicKeyCose = attested.cosePublicKey,
        signCount = response.rawAuthenticatorData.signCount,
    )
}
