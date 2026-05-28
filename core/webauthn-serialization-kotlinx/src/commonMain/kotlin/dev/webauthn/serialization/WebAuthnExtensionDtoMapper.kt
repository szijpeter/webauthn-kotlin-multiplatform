package dev.webauthn.serialization

import dev.webauthn.model.AuthenticationExtensionsClientInputs
import dev.webauthn.model.AuthenticationExtensionsClientOutputs
import dev.webauthn.model.AuthenticationExtensionsPRFValues
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.LargeBlobExtensionInput
import dev.webauthn.model.LargeBlobExtensionOutput
import dev.webauthn.model.PrfExtensionInput
import dev.webauthn.model.PrfExtensionOutput
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

internal object WebAuthnExtensionDtoMapper {
    fun fromModel(value: AuthenticationExtensionsClientInputs): AuthenticationExtensionsClientInputsDto {
        return AuthenticationExtensionsClientInputsDto(
            prf = value.prf?.let { prf ->
                PrfExtensionInputDto(
                    eval = prf.eval?.let(::fromModel),
                    evalByCredential = prf.evalByCredential?.mapValues { fromModel(it.value) },
                )
            },
            largeBlob = value.largeBlob?.let { largeBlob ->
                LargeBlobExtensionInputDto(
                    support = largeBlob.support?.name?.lowercase(),
                    read = largeBlob.read,
                    write = largeBlob.write?.toBase64Url(),
                )
            },
            relatedOrigins = value.relatedOrigins,
        )
    }

    fun fromModel(value: AuthenticationExtensionsClientOutputs): AuthenticationExtensionsClientOutputsDto {
        return AuthenticationExtensionsClientOutputsDto(
            prf = value.prf?.let { prf ->
                PrfExtensionOutputDto(
                    enabled = prf.enabled,
                    results = prf.results?.let(::fromModel),
                )
            },
            largeBlob = value.largeBlob?.let { largeBlob ->
                LargeBlobExtensionOutputDto(
                    supported = largeBlob.supported,
                    blob = largeBlob.blob?.toBase64Url(),
                    written = largeBlob.written,
                )
            },
        )
    }

    @Suppress("CyclomaticComplexMethod")
    fun toModelValidated(
        value: AuthenticationExtensionsClientInputsDto,
        fieldPrefix: String,
    ): ValidationResult<AuthenticationExtensionsClientInputs> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val prf = value.prf?.let { prf ->
            val eval = prf.eval?.let { prfValues ->
                when (val parsed = toModelValidated(prfValues, "$fieldPrefix.prf.eval")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            val evalByCredential = prf.evalByCredential?.let { evalMap ->
                buildMap {
                    for ((credentialId, prfValues) in evalMap) {
                        when (
                            val parsed = toModelValidated(
                                prfValues,
                                "$fieldPrefix.prf.evalByCredential.$credentialId",
                            )
                        ) {
                            is ValidationResult.Valid -> put(credentialId, parsed.value)
                            is ValidationResult.Invalid -> errors += parsed.errors
                        }
                    }
                }
            }
            PrfExtensionInput(eval = eval, evalByCredential = evalByCredential)
        }

        val largeBlob = value.largeBlob?.let { largeBlob ->
            val support = largeBlob.support?.let {
                LargeBlobExtensionInput.LargeBlobSupport.entries.find {
                    entry -> entry.name.equals(it, ignoreCase = true)
                } ?: run {
                    errors += WebAuthnValidationError.InvalidValue(
                        field = "$fieldPrefix.largeBlob.support",
                        message = "Unknown support value: $it",
                    )
                    null
                }
            }
            val write = largeBlob.write?.let {
                when (val parsed = parseBase64Url(it, "$fieldPrefix.largeBlob.write")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            LargeBlobExtensionInput(
                support = support,
                read = largeBlob.read,
                write = write,
            )
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(
                AuthenticationExtensionsClientInputs(
                    prf = prf,
                    largeBlob = largeBlob,
                    relatedOrigins = value.relatedOrigins,
                ),
            )
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    fun toModelValidated(
        value: AuthenticationExtensionsClientOutputsDto,
        fieldPrefix: String,
    ): ValidationResult<AuthenticationExtensionsClientOutputs> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val prf = value.prf?.let { prf ->
            val results = prf.results?.let { prfValues ->
                when (val parsed = toModelValidated(prfValues, "$fieldPrefix.prf.results")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            PrfExtensionOutput(enabled = prf.enabled, results = results)
        }

        val largeBlob = value.largeBlob?.let { largeBlob ->
            val blob = largeBlob.blob?.let {
                when (val parsed = parseBase64Url(it, "$fieldPrefix.largeBlob.blob")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            LargeBlobExtensionOutput(
                supported = largeBlob.supported,
                blob = blob,
                written = largeBlob.written,
            )
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(
                AuthenticationExtensionsClientOutputs(
                    prf = prf,
                    largeBlob = largeBlob,
                ),
            )
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    private fun fromModel(value: AuthenticationExtensionsPRFValues): PrfValuesDto {
        return PrfValuesDto(
            first = value.first.toBase64Url(),
            second = value.second?.toBase64Url(),
        )
    }

    private fun toModelValidated(
        value: PrfValuesDto,
        fieldPrefix: String,
    ): ValidationResult<AuthenticationExtensionsPRFValues> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val first = when (val parsed = parseBase64Url(value.first, "$fieldPrefix.first")) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                errors += parsed.errors
                null
            }
        }

        val second = value.second?.let {
            when (val parsed = parseBase64Url(it, "$fieldPrefix.second")) {
                is ValidationResult.Valid -> parsed.value
                is ValidationResult.Invalid -> {
                    errors += parsed.errors
                    null
                }
            }
        }

        return if (first != null && errors.isEmpty()) {
            ValidationResult.Valid(
                AuthenticationExtensionsPRFValues(
                    first = first,
                    second = second,
                ),
            )
        } else {
            ValidationResult.Invalid(errors)
        }
    }
}

private fun parseBase64Url(
    value: String,
    field: String,
): ValidationResult<Base64UrlBytes> {
    return Base64UrlBytes.parse(value, field)
}

private fun Base64UrlBytes.toBase64Url(): String = encoded()
