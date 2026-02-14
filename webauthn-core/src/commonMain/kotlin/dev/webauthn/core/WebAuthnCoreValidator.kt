package dev.webauthn.core

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

public object WebAuthnCoreValidator {
    public fun validateClientData(
        clientData: CollectedClientData,
        expectedType: String,
        expectedChallenge: String,
        expectedOrigin: Origin,
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        if (clientData.type != expectedType) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "clientData.type",
                message = "Expected $expectedType but got ${clientData.type}",
            )
        }

        if (clientData.challenge.value.encoded() != expectedChallenge) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "clientData.challenge",
                message = "Challenge does not match the original ceremony challenge",
            )
        }

        if (clientData.origin != expectedOrigin) {
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

    public fun validateRegistration(input: RegistrationValidationInput): ValidationResult<RegistrationValidationOutput> {
        val clientDataResult = validateClientData(
            clientData = input.clientData,
            expectedType = "webauthn.create",
            expectedChallenge = input.options.challenge.value.encoded(),
            expectedOrigin = input.expectedOrigin,
        )
        if (clientDataResult is ValidationResult.Invalid) {
            return clientDataResult
        }

        val authDataResult = validateAuthenticatorData(input.response.rawAuthenticatorData, 0L)
        if (authDataResult is ValidationResult.Invalid) {
            return authDataResult
        }

        return ValidationResult.Valid(
            RegistrationValidationOutput(
                credentialId = input.response.credentialId,
                signCount = input.response.rawAuthenticatorData.signCount,
            ),
        )
    }

    public fun validateAuthentication(input: AuthenticationValidationInput): ValidationResult<AuthenticationValidationOutput> {
        val clientDataResult = validateClientData(
            clientData = input.clientData,
            expectedType = "webauthn.get",
            expectedChallenge = input.options.challenge.value.encoded(),
            expectedOrigin = input.expectedOrigin,
        )
        if (clientDataResult is ValidationResult.Invalid) {
            return clientDataResult
        }

        val authDataResult = validateAuthenticatorData(input.response.authenticatorData, input.previousSignCount)
        if (authDataResult is ValidationResult.Invalid) {
            return authDataResult
        }

        return ValidationResult.Valid(
            AuthenticationValidationOutput(
                credentialId = input.response.credentialId,
                signCount = input.response.authenticatorData.signCount,
            ),
        )
    }

    public fun validateAuthenticatorData(
        data: AuthenticatorData,
        previousSignCount: Long,
    ): ValidationResult<Unit> {
        val errors = mutableListOf<WebAuthnValidationError>()

        if (data.rpIdHash.size != 32) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "authenticatorData.rpIdHash",
                message = "rpIdHash must be 32 bytes",
            )
        }

        val upSet = (data.flags and USER_PRESENCE_FLAG) != 0
        if (!upSet) {
            errors += WebAuthnValidationError.InvalidValue(
                field = "authenticatorData.flags",
                message = "User presence flag must be set",
            )
        }

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
}
