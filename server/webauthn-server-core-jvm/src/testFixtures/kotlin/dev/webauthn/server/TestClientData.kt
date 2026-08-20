package dev.webauthn.server

import dev.webauthn.json.CollectedClientDataDecoder
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** JSON decoder shared by server contract and transport tests. */
public object TestCollectedClientDataDecoder :
    CollectedClientDataDecoder by KotlinxWebAuthnJsonCodec()

/** Encodes signed client-data bytes for server tests that construct raw responses directly. */
public fun encodeTestCollectedClientData(
    type: String,
    challenge: Challenge,
    origin: Origin,
): String {
    return encodeTestCollectedClientDataBytes(
        CollectedClientData(type = type, challenge = challenge, origin = origin),
    ).encoded()
}

/** Test-only request factory that makes constructed client data authoritative in the raw response. */
@Suppress("FunctionName")
public fun RegistrationFinishRequest(
    rawResponse: RawRegistrationResponse,
    clientData: CollectedClientData,
): RegistrationFinishRequest = RegistrationFinishRequest(
    response = rawResponse.copy(clientDataJson = encodeTestCollectedClientDataBytes(clientData)),
)

/** Test-only request factory that makes constructed client data authoritative in the raw response. */
@Suppress("FunctionName")
public fun AuthenticationFinishRequest(
    rawResponse: RawAuthenticationResponse,
    clientData: CollectedClientData,
): AuthenticationFinishRequest = AuthenticationFinishRequest(
    response = rawResponse.copy(clientDataJson = encodeTestCollectedClientDataBytes(clientData)),
)

private fun encodeTestCollectedClientDataBytes(value: CollectedClientData): Base64UrlBytes {
    val json = buildJsonObject {
        put("type", JsonPrimitive(value.type))
        put("challenge", JsonPrimitive(value.challenge.value.encoded()))
        put("origin", JsonPrimitive(value.origin.value))
        value.crossOrigin?.let { put("crossOrigin", JsonPrimitive(it)) }
    }
    return Base64UrlBytes.fromBytes(json.toString().encodeToByteArray())
}
