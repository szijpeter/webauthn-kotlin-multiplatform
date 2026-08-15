package dev.webauthn.network

import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult

/**
 * Serialization contract for a Ktor-backed passkey backend.
 *
 * The transport intentionally owns no JSON implementation. Applications that use the default
 * `/webauthn/…` payloads can add the Kotlinx adapter artifact; alternate backend contracts can
 * implement this interface without resolving Kotlinx serialization.
 */
public interface KtorPasskeyContractCodec<
    RegistrationInput,
    AuthenticationInput,
    RegistrationOutput,
    AuthenticationOutput,
> {
    public fun encodeRegistrationStart(input: RegistrationInput): String

    public fun decodeRegistrationStart(value: String): ValidationResult<PublicKeyCredentialCreationOptions>

    public fun encodeRegistrationFinish(response: RawRegistrationResponse): String

    public fun decodeRegistrationFinish(value: String): RegistrationOutput

    public fun encodeAuthenticationStart(input: AuthenticationInput): String

    public fun decodeAuthenticationStart(value: String): ValidationResult<PublicKeyCredentialRequestOptions>

    public fun encodeAuthenticationFinish(response: RawAuthenticationResponse): String

    public fun decodeAuthenticationFinish(value: String): AuthenticationOutput

    /** Returns a safe backend error message when available, otherwise `null`. */
    public fun decodeError(value: String): String?
}
