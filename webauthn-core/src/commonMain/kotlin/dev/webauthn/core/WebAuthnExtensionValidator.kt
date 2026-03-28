package dev.webauthn.core

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.model.ValidationResult

/**
 * Default implementation of extension validation logic.
 *
 * Delegates to a [CompositeExtensionHook] containing per-extension hooks for
 * all currently supported L3 extensions:
 * - [PrfExtensionHook] — HMAC Secret Extension (prf)
 * - [LargeBlobExtensionHook] — Large blob storage extension (largeBlob)
 *
 * To validate only a subset of extensions or add custom validation, compose your
 * own hook pipeline using [CompositeExtensionHook] or individual hooks directly.
 */
@ExperimentalWebAuthnL3Api
public object WebAuthnExtensionValidator : WebAuthnExtensionHook by CompositeExtensionHook(
    listOf(
        LargeBlobExtensionHook,
        PrfExtensionHook,
    ),
)
