package dev.webauthn.documentation.examples

import dev.webauthn.model.ValidationResult
import dev.webauthn.protocol.ParsedAuthenticatorData
import dev.webauthn.protocol.WebAuthnProtocolParser

// docs-region protocol-authenticator-data
fun parseAuthenticatorData(bytes: ByteArray): ValidationResult<ParsedAuthenticatorData> {
    return WebAuthnProtocolParser.parseAuthenticatorData(bytes)
}
// docs-endregion protocol-authenticator-data
