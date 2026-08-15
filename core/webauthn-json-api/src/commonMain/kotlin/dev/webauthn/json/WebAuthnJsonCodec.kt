package dev.webauthn.json

import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult

/**
 * Technology-neutral JSON boundary for WebAuthn ceremony values.
 *
 * Implementations own their JSON library and wire representation. Callers receive typed options and raw,
 * untrusted credential responses, and must pass those responses through protocol interpretation before
 * ceremony validation.
 */
public interface WebAuthnJsonCodec {
    public fun encodeCreationOptions(value: PublicKeyCredentialCreationOptions): String

    public fun decodeCreationOptions(value: String): ValidationResult<PublicKeyCredentialCreationOptions>

    public fun encodeRequestOptions(value: PublicKeyCredentialRequestOptions): String

    public fun decodeRequestOptions(value: String): ValidationResult<PublicKeyCredentialRequestOptions>

    public fun encodeRegistrationResponse(value: RawRegistrationResponse): String

    public fun decodeRegistrationResponse(value: String): ValidationResult<RawRegistrationResponse>

    public fun encodeAuthenticationResponse(value: RawAuthenticationResponse): String

    public fun decodeAuthenticationResponse(value: String): ValidationResult<RawAuthenticationResponse>

    public fun decodeCollectedClientData(value: ByteArray): ValidationResult<CollectedClientData>
}
