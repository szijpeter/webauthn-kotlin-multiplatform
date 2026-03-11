package dev.webauthn.core

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/** User verification policy mapped from ceremony options to core validation behavior. */
public enum class UserVerificationPolicy {
    REQUIRED,
    PREFERRED,
    DISCOURAGED,
}

/** Core validator implementing the WebAuthn L3 ceremony checks shared by server adapters. */
public object WebAuthnCoreValidator {
    /**
     * W3C WebAuthn L3:
     * - §7.1. Registering a New Credential (Steps 7, 8, 9, 10, 11)
     * - §7.2. Verifying an Authentication Assertion (Steps 10, 11, 12, 13, 14, 15)
     */
    public fun validateClientData(
        clientData: CollectedClientData,
        expectedType: String,
        expectedChallenge: String,
        expectedOrigin: Origin,
        allowedOrigins: Set<Origin> = emptySet(),
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        // W3C WebAuthn L3 §7.1 Step 8 / §7.2 Step 11: Verify that the value of
        // C.type is webauthn.create or webauthn.get.
        if (clientData.type != expectedType) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "clientData.type",
                message = "Expected $expectedType but got ${clientData.type}",
            )
        }

        // W3C WebAuthn L3 §7.1 Step 9 / §7.2 Step 12: Verify that the value of
        // C.challenge equals the base64url encoding of options.challenge.
        if (clientData.challenge.value.encoded() != expectedChallenge) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "clientData.challenge",
                message = "Challenge does not match the original ceremony challenge",
            )
        }

        // W3C WebAuthn L3 §7.1 Step 10 / §7.2 Step 13: Verify that the value of
        // C.origin matches the Relying Party's origin (including related origins).
        val validOrigins = setOf(expectedOrigin) + allowedOrigins
        if (!validOrigins.contains(clientData.origin)) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "clientData.origin",
                message = "Origin does not match relying party expectations",
            )
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    public fun validateRegistration(
        input: RegistrationValidationInput,
    ): ValidationResult<RegistrationValidationOutput> {
        val clientDataResult = validateClientData(
            clientData = input.clientData,
            expectedType = "webauthn.create",
            expectedChallenge = input.options.challenge.value.encoded(),
            expectedOrigin = input.expectedOrigin,
            allowedOrigins = input.allowedOrigins,
        )
        if (clientDataResult is ValidationResult.Invalid) {
            return clientDataResult
        }

        val authDataResult = validateAuthenticatorData(
            data = input.response.rawAuthenticatorData,
            previousSignCount = 0L,
            uvPolicy = input.userVerificationPolicy,
        )
        if (authDataResult is ValidationResult.Invalid) {
            return authDataResult
        }

        return ValidationResult.Valid(
            RegistrationValidationOutput(
                credentialId = input.response.credentialId,
                signCount = input.response.rawAuthenticatorData.signCount,
                extensions = input.response.extensions,
            ),
        )
    }

    public fun validateAuthentication(
        input: AuthenticationValidationInput,
    ): ValidationResult<AuthenticationValidationOutput> {
        val clientDataResult = validateClientData(
            clientData = input.clientData,
            expectedType = "webauthn.get",
            expectedChallenge = input.options.challenge.value.encoded(),
            expectedOrigin = input.expectedOrigin,
            allowedOrigins = input.allowedOrigins,
        )
        if (clientDataResult is ValidationResult.Invalid) {
            return clientDataResult
        }

        val authDataResult = validateAuthenticatorData(
            data = input.response.authenticatorData,
            previousSignCount = input.previousSignCount,
            uvPolicy = input.userVerificationPolicy,
        )
        if (authDataResult is ValidationResult.Invalid) {
            return authDataResult
        }

        return ValidationResult.Valid(
            AuthenticationValidationOutput(
                credentialId = input.response.credentialId,
                signCount = input.response.authenticatorData.signCount,
                extensions = input.response.extensions,
            ),
        )
    }

    /**
     * W3C WebAuthn L3:
     * - §7.1. Registering a New Credential (Steps 14, 15, 16)
     * - §7.2. Verifying an Authentication Assertion (Steps 18, 19, 20, 21, 22, 23, 24)
     */
    public fun validateAuthenticatorData(
        data: AuthenticatorData,
        previousSignCount: Long,
        uvPolicy: UserVerificationPolicy = UserVerificationPolicy.PREFERRED,
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        // W3C WebAuthn L3 §7.1 Step 15 / §7.2 Step 20: verify that the User Presence
        // bit of the flags in authData is set.
        val upSet = (data.flags and USER_PRESENCE_FLAG) != 0
        if (!upSet) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "authenticatorData.flags",
                message = "User presence flag must be set",
            )
        }

        // W3C WebAuthn L3 §7.2 Step 21: if user verification is required, verify that
        // the User Verification bit of the flags in authData is set.
        if (uvPolicy == UserVerificationPolicy.REQUIRED) {
            val uvSet = (data.flags and USER_VERIFICATION_FLAG) != 0
            if (!uvSet) {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "authenticatorData.flags",
                    message = "User verification flag must be set when UV is required",
                )
            }
        }

        // W3C WebAuthn L3 §7.1 Step 16 / §7.2 Step 22: Verify that the
        // "backup eligibility" and "backup state" bits match.
        val beSet = (data.flags and BACKUP_ELIGIBLE_FLAG) != 0
        val bsSet = (data.flags and BACKUP_STATE_FLAG) != 0
        if (bsSet && !beSet) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "authenticatorData.flags",
                message = "Backup state flag must not be set when backup eligible flag is clear",
            )
        }

        // W3C WebAuthn L3 §7.2 Step 24: Verify that the signature counter value
        // is strictly greater than the stored counter.
        if (previousSignCount > 0 && data.signCount > 0 && data.signCount <= previousSignCount) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "authenticatorData.signCount",
                message = "Signature counter did not increase",
            )
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    public fun requireAllowedCredential(
        response: AuthenticationResponse,
        allowedCredentialIds: Set<String>,
    ): ValidationResult<Unit> {
        if (allowedCredentialIds.isEmpty()) {
            return ValidationResult.Valid(Unit)
        }
        return if (allowedCredentialIds.contains(response.credentialId.value.encoded())) {
            ValidationResult.Valid(Unit)
        } else {
            ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = "credentialId",
                        message = "Credential ID is not part of allowCredentials",
                    ),
                ),
            )
        }
    }

    public const val USER_PRESENCE_FLAG: Int = 0x01
    public const val USER_VERIFICATION_FLAG: Int = 0x04
    public const val BACKUP_ELIGIBLE_FLAG: Int = 0x08
    public const val BACKUP_STATE_FLAG: Int = 0x10
}
