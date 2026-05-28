package dev.webauthn.client

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** kotlinx.serialization-backed implementation of [PasskeyJsonMapper]. */
public class KotlinxPasskeyJsonMapper(
    private val json: Json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    },
) : PasskeyJsonMapper {
    override fun <T> encode(
        value: T,
        serializer: SerializationStrategy<T>,
    ): String {
        return json.encodeToString(serializer, value)
    }

    override fun <T> decode(
        payload: String,
        deserializer: DeserializationStrategy<T>,
    ): T {
        return json.decodeFromString(deserializer, payload)
    }
}
