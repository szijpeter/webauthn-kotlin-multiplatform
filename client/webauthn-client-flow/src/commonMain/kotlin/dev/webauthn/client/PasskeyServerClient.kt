@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult

/** Backend contract used by [PasskeyController] to start/finish ceremonies. */
public interface PasskeyServerClient<RegisterParams, SignInParams> {
    /**
     * Starts registration by fetching server-issued creation options for the supplied [params].
     *
     * Implementations should return a [ValidationResult.Invalid] when the backend response
     * cannot be decoded into trustworthy WebAuthn creation options.
     */
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
        response: RawRegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult

    /**
     * Starts authentication by fetching server-issued request options for the supplied [params].
     *
     * Implementations should return a [ValidationResult.Invalid] when the backend response
     * cannot be decoded into trustworthy WebAuthn request options.
     */
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
        response: RawAuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult
}
