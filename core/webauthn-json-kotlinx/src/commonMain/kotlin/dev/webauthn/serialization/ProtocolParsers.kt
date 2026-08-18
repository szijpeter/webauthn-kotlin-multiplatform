package dev.webauthn.serialization

import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

@Serializable
private data class CollectedClientDataJsonDto(
    val type: String,
    val challenge: String,
    val origin: String,
    val crossOrigin: Boolean? = null,
)

private val clientDataJsonParser = Json {
    ignoreUnknownKeys = true
}

internal fun parseCollectedClientDataJson(
    bytes: ByteArray,
    field: String = "clientDataJSON",
): ValidationResult<CollectedClientData> {
    val text = runCatching {
        bytes.decodeToString(throwOnInvalidSequence = true)
    }.getOrElse {
        return ValidationResult.Invalid(
            [
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "clientDataJSON must be valid UTF-8 JSON",
                ),
            ],
        )
    }

    val jsonObject = runCatching {
        clientDataJsonParser.parseToJsonElement(text).jsonObject
    }.getOrElse {
        return ValidationResult.Invalid(
            [
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "clientDataJSON must be a valid JSON object",
                ),
            ],
        )
    }

    if (CLIENT_DATA_TYPE !in jsonObject) {
        return missingField("$field.$CLIENT_DATA_TYPE", CLIENT_DATA_TYPE)
    }
    if (CLIENT_DATA_CHALLENGE !in jsonObject) {
        return missingField("$field.$CLIENT_DATA_CHALLENGE", CLIENT_DATA_CHALLENGE)
    }
    if (CLIENT_DATA_ORIGIN !in jsonObject) {
        return missingField("$field.$CLIENT_DATA_ORIGIN", CLIENT_DATA_ORIGIN)
    }

    val dto = runCatching {
        clientDataJsonParser.decodeFromString<CollectedClientDataJsonDto>(text)
    }.getOrElse {
        return ValidationResult.Invalid(
            [
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "clientDataJSON must use valid JSON field types",
                ),
            ],
        )
    }

    val parsedChallenge = when (val result = Challenge.parse(dto.challenge)) {
        is ValidationResult.Valid -> result.value
        is ValidationResult.Invalid -> return reprefixedInvalid(result.errors, "challenge", "$field.challenge")
    }
    val parsedOrigin = when (val result = Origin.parse(dto.origin)) {
        is ValidationResult.Valid -> result.value
        is ValidationResult.Invalid -> return reprefixedInvalid(result.errors, "origin", "$field.origin")
    }

    return ValidationResult.Valid(
        CollectedClientData(
            type = dto.type,
            challenge = parsedChallenge,
            origin = parsedOrigin,
            crossOrigin = dto.crossOrigin,
        ),
    )
}

private fun <T> missingField(field: String, label: String): ValidationResult<T> {
    return ValidationResult.Invalid(
        [
            WebAuthnValidationError.MissingValue(
                field = field,
                message = "clientDataJSON is missing $label",
            ),
        ],
    )
}

private fun <T> invalidFormat(field: String, message: String): ValidationResult<T> {
    return ValidationResult.Invalid(
        [
            WebAuthnValidationError.InvalidFormat(
                field = field,
                message = message,
            ),
        ],
    )
}

private fun reprefixedInvalid(
    errors: List<WebAuthnValidationError>,
    source: String,
    target: String,
): ValidationResult.Invalid {
    return ValidationResult.Invalid(
        errors.map { error ->
            when (error) {
                is WebAuthnValidationError.InvalidFormat -> error.copy(field = error.field.replace(source, target))
                is WebAuthnValidationError.InvalidValue -> error.copy(field = error.field.replace(source, target))
                is WebAuthnValidationError.MissingValue -> error.copy(field = error.field.replace(source, target))
            }
        },
    )
}

private const val CLIENT_DATA_TYPE = "type"
private const val CLIENT_DATA_CHALLENGE = "challenge"
private const val CLIENT_DATA_ORIGIN = "origin"
