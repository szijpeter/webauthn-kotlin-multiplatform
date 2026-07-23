package examples

import dev.webauthn.core.LargeBlobExtensionHook
import dev.webauthn.model.ExperimentalWebAuthnL3Api

// docs-region composite-extension
import dev.webauthn.core.CompositeExtensionHook
import dev.webauthn.core.PrfExtensionHook
import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ValidationResult

@OptIn(ExperimentalWebAuthnL3Api::class)
fun validatePrfOnly(
    inputs: AuthenticationExtensionsClientInputs?,
    outputs: AuthenticationExtensionsClientOutputs?,
): ValidationResult<Unit> {
    val prfOnly = CompositeExtensionHook([PrfExtensionHook])
    return prfOnly.validateAuthenticationExtensions(inputs, outputs)
}
// docs-endregion composite-extension

@OptIn(ExperimentalWebAuthnL3Api::class)
fun compositeExtensionHookExample() {
    // docs-region composite-extension-kdoc
    val hooks = CompositeExtensionHook([PrfExtensionHook, LargeBlobExtensionHook])
    // docs-endregion composite-extension-kdoc
}
