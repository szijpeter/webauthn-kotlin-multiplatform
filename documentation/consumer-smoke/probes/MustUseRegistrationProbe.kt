package smoke.server

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.core.WebAuthnCoreValidator

fun ignoreRegistrationResult(input: RegistrationValidationInput) {
    WebAuthnCoreValidator.validateRegistration(input)
}
