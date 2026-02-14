package dev.webauthn.network

import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import kotlin.test.Test
import kotlin.test.assertEquals

class NetworkPayloadTest {
    @Test
    fun toFinishPayloadMapsChallengeAndOrigin() {
        val clientData = CollectedClientData(
            type = "webauthn.create",
            challenge = Challenge.fromBytes(ByteArray(16) { 1 }),
            origin = Origin.parseOrThrow("https://example.com"),
        )

        val payload = clientData.toRegistrationFinishPayload(
            RegistrationResponseDto(
                id = "YWFhYWFhYWFhYWFhYWFhYQ",
                rawId = "YWFhYWFhYWFhYWFhYWFhYQ",
                response = RegistrationResponsePayloadDto(
                    clientDataJson = "YWFhYWFhYWFhYWFhYWFhYQ",
                    attestationObject = "YWFhYWFhYWFhYWFhYWFhYQ",
                ),
            ),
        )

        assertEquals(clientData.origin.value, payload.origin)
        assertEquals(clientData.challenge.value.encoded(), payload.challenge)
    }
}
