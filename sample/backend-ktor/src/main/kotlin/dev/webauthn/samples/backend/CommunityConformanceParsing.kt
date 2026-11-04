package dev.webauthn.samples.backend

import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

internal val conformanceJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = false
}

internal fun JsonObject.parseRawRegistrationResponse(): RawRegistrationResponse? {
    val responseDto = runCatching { registrationResponseDto() }.getOrNull() ?: return null
    return when (val result = WebAuthnDtoMapper.toRawModel(responseDto)) {
        is ValidationResult.Valid -> result.value
        is ValidationResult.Invalid -> null
    }
}

private fun JsonObject.registrationResponseDto(): RegistrationResponseDto {
    val credentialJson = this["response"]
        ?.jsonObject
        ?.takeIf { it["response"] is JsonObject }
        ?: this
    val normalizedCredentialJson = credentialJson.withRawIdFallback()
    return runCatching {
        conformanceJson.decodeFromJsonElement(RegistrationResponseDto.serializer(), normalizedCredentialJson)
    }.getOrElse { error ->
        throw IllegalArgumentException("Registration response payload is invalid: ${error.message}", error)
    }
}

private fun JsonObject.withRawIdFallback(): JsonObject {
    if ("rawId" in this) {
        return this
    }
    val id = stringValue("id") ?: return this
    return buildJsonObject {
        this@withRawIdFallback.forEach { (key, value) -> put(key, value) }
        put("rawId", id)
    }
}
