@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult

/** Backend contract used by [PasskeyController] to start/finish ceremonies. */
public interface PasskeyServerClient<RegisterParams, SignInParams> {
    public suspend fun getRegisterOptions(params: RegisterParams): ValidationResult<PublicKeyCredentialCreationOptions>

    /**
     * Completes registration.
     *
     * `challengeAsBase64Url` is an echoed client value and must be checked against
     * server-trusted state (or an equivalent signed challenge envelope). It is
     * not authoritative on its own.
     */
    public suspend fun finishRegister(
        params: RegisterParams,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult

    public suspend fun getSignInOptions(params: SignInParams): ValidationResult<PublicKeyCredentialRequestOptions>

    /**
     * Completes authentication.
     *
     * `challengeAsBase64Url` is an echoed client value and must be checked against
     * server-trusted state (or an equivalent signed challenge envelope). It is
     * not authoritative on its own.
     */
    public suspend fun finishSignIn(
        params: SignInParams,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult
}
