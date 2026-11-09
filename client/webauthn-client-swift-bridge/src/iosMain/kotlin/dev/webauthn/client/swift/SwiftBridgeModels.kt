package dev.webauthn.client.swift

import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PlatformCapability
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject

/** Stable, non-generic result exported only to the internal Swift adapter. */
public class SwiftPasskeyBridgeResult internal constructor(
    public val responseJson: String?,
    public val errorCode: String?,
    public val errorMessage: String?,
) {
    public val isSuccess: Boolean
        get() = responseJson != null && errorCode == null && errorMessage == null
}

/** Capability snapshot serialized through a primitive JSON bridge boundary. */
public class SwiftPasskeyBridgeCapabilities internal constructor(
    public val valuesJson: String,
    public val reportedCount: Int,
)

internal data class SwiftBridgeFailure(
    val code: String,
    val message: String,
)

internal fun success(responseJson: String): SwiftPasskeyBridgeResult =
    SwiftPasskeyBridgeResult(
        responseJson = responseJson,
        errorCode = null,
        errorMessage = null,
    )

internal fun failure(code: String, message: String): SwiftPasskeyBridgeResult =
    SwiftPasskeyBridgeResult(
        responseJson = null,
        errorCode = code,
        errorMessage = message,
    )

internal fun PasskeyClientError.toSwiftBridgeFailure(): SwiftBridgeFailure = when (this) {
    is PasskeyClientError.UserCancelled -> SwiftBridgeFailure("userCancelled", message)
    is PasskeyClientError.NoCredential -> SwiftBridgeFailure("noCredential", message)
    is PasskeyClientError.InvalidOptions -> SwiftBridgeFailure("invalidOptions", message)
    is PasskeyClientError.Platform -> SwiftBridgeFailure("platform", message)
    is PasskeyClientError.Codec -> SwiftBridgeFailure("codec", message)
}

internal fun PasskeyCapabilities.toSwiftBridgeCapabilities(): SwiftPasskeyBridgeCapabilities {
    val values = buildJsonArray {
        support.entries
            .sortedBy { (capability, _) -> capability.swiftSortKey() }
            .forEach { (capability, support) ->
                add(
                    buildJsonObject {
                        put("kind", JsonPrimitive(capability.swiftKind()))
                        put("id", JsonPrimitive(capability.swiftIdentifier()))
                        put("support", JsonPrimitive(support.swiftValue()))
                    },
                )
            }
    }
    return SwiftPasskeyBridgeCapabilities(
        valuesJson = Json.encodeToString(values),
        reportedCount = support.size,
    )
}

private fun PasskeyCapability.swiftSortKey(): String = "${swiftKind()}\u0000${swiftIdentifier()}"

private fun PasskeyCapability.swiftKind(): String = when (this) {
    is PasskeyCapability.Extension -> "extension"
    is PasskeyCapability.Platform -> "platform"
}

private fun PasskeyCapability.swiftIdentifier(): String = when (this) {
    is PasskeyCapability.Extension -> extension.identifier
    is PasskeyCapability.Platform -> when (val value = feature) {
        PlatformCapability.SecurityKey -> "securityKey"
        is PlatformCapability.Custom -> value.id
    }
}

private fun CapabilitySupport.swiftValue(): String = when (this) {
    CapabilitySupport.SUPPORTED -> "supported"
    CapabilitySupport.UNSUPPORTED -> "unsupported"
    CapabilitySupport.UNKNOWN -> "unknown"
}
