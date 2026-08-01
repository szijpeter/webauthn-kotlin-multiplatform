package dev.webauthn.samples.backend

import dev.webauthn.model.Origin
import dev.webauthn.model.ResidentKeyRequirement
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.server.RegistrationStartRequest
import java.security.MessageDigest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

internal fun JsonObject.toRegistrationStartRequest(
    username: String,
    config: CommunityConformanceConfig,
): RegistrationStartRequest {
    val authenticatorSelection = this["authenticatorSelection"]?.jsonObject
    return RegistrationStartRequest(
        rpId = RpId.parseOrThrow(stringValue("rpId") ?: config.rpId),
        rpName = stringValue("rpName") ?: config.rpName,
        origin = Origin.parseOrThrow(stringValue("origin") ?: config.origin),
        userName = username,
        userDisplayName = stringValue("displayName") ?: stringValue("userDisplayName") ?: username,
        userHandle = deterministicUserHandle(username),
        residentKey = authenticatorSelection.toResidentKeyRequirement(),
        userVerification = authenticatorSelection.toUserVerificationRequirement(),
    )
}

internal fun JsonObject.communityOptionsResponse(
    optionsJson: JsonObject,
): JsonObject {
    val payload = this
    return buildJsonObject {
        put("status", "ok")
        put("errorMessage", "")
        optionsJson.forEach { (key, value) -> put(key, value) }
        payload.stringValue("attestation")?.let { put("attestation", it) }
        payload["authenticatorSelection"]?.let { put("authenticatorSelection", it) }
        payload["extensions"]?.let { put("extensions", it) }
    }
}

internal fun JsonObject.stringValue(key: String): String? =
    this[key]?.jsonPrimitive?.contentOrNull

private fun JsonObject?.toResidentKeyRequirement(): ResidentKeyRequirement {
    val residentKey = this?.stringValue("residentKey")?.toResidentKeyRequirement()
    if (residentKey != null) {
        return residentKey
    }
    return when (this?.get("requireResidentKey")?.jsonPrimitive?.booleanOrNull) {
        true -> ResidentKeyRequirement.REQUIRED
        false,
        null,
        -> ResidentKeyRequirement.PREFERRED
    }
}

private fun JsonObject?.toUserVerificationRequirement(): UserVerificationRequirement =
    this?.stringValue("userVerification")?.toUserVerificationRequirement()
        ?: UserVerificationRequirement.PREFERRED

private fun String.toResidentKeyRequirement(): ResidentKeyRequirement? =
    when (lowercase()) {
        "required" -> ResidentKeyRequirement.REQUIRED
        "preferred" -> ResidentKeyRequirement.PREFERRED
        "discouraged" -> ResidentKeyRequirement.DISCOURAGED
        else -> null
    }

private fun String.toUserVerificationRequirement(): UserVerificationRequirement? =
    when (lowercase()) {
        "required" -> UserVerificationRequirement.REQUIRED
        "preferred" -> UserVerificationRequirement.PREFERRED
        "discouraged" -> UserVerificationRequirement.DISCOURAGED
        else -> null
    }

private fun deterministicUserHandle(username: String): UserHandle {
    val digest = MessageDigest.getInstance("SHA-256")
        .digest(username.encodeToByteArray())
    return UserHandle.fromBytes(digest)
}
