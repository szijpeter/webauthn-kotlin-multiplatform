package dev.webauthn.samples.backend

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.serialization.RegistrationResponseDto
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject

internal val conformanceJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = false
}

@Serializable
private data class CommunityCollectedClientDataDto(
    val type: String,
    val challenge: String,
    val origin: String,
)

@Serializable
private data class CommunityRegistrationFinishWrapper(
    val response: RegistrationResponseDto,
    val clientDataType: String? = null,
    val challenge: String? = null,
    val origin: String? = null,
)

internal fun JsonObject.parseRegistrationResponseDto(): RegistrationResponseDto? =
    runCatching { registrationResponseDto() }.getOrNull()

private fun JsonObject.registrationResponseDto(): RegistrationResponseDto {
    val credentialJson = this["response"]
        ?.jsonObject
        ?.takeIf { it["response"] is JsonObject }
        ?: this
    return runCatching {
        conformanceJson.decodeFromJsonElement(RegistrationResponseDto.serializer(), credentialJson)
    }.getOrElse { error ->
        throw IllegalArgumentException("Registration response payload is invalid: ${error.message}", error)
    }
}

internal fun JsonObject.parseClientData(response: RegistrationResponseDto): CollectedClientData? =
    runCatching { clientData(response) }.getOrNull()

private fun JsonObject.clientData(response: RegistrationResponseDto): CollectedClientData {
    val wrapper = runCatching {
        conformanceJson.decodeFromJsonElement(CommunityRegistrationFinishWrapper.serializer(), this)
    }.getOrNull()
    if (wrapper?.clientDataType != null && wrapper.challenge != null && wrapper.origin != null) {
        return CollectedClientData(
            type = wrapper.clientDataType,
            challenge = Challenge.parseOrThrow(wrapper.challenge),
            origin = Origin.parseOrThrow(wrapper.origin),
        )
    }

    val clientDataBytes = Base64UrlBytes.parseOrThrow(response.response.clientDataJson, "clientDataJSON").bytes()
    val clientDataJson = clientDataBytes.decodeToString()
    val clientData = runCatching {
        conformanceJson.decodeFromString(CommunityCollectedClientDataDto.serializer(), clientDataJson)
    }.getOrElse { error ->
        throw IllegalArgumentException("clientDataJSON is invalid: ${error.message}", error)
    }
    return CollectedClientData(
        type = clientData.type,
        challenge = Challenge.parseOrThrow(clientData.challenge),
        origin = Origin.parseOrThrow(clientData.origin),
    )
}
