@file:Suppress("UndocumentedPublicFunction")

package dev.webauthn.client

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.serializer

@OptIn(ExperimentalSerializationApi::class)
public inline fun <reified T> T.serializeToJson(
    mapper: PasskeyJsonMapper,
    serializer: SerializationStrategy<T> = serializer(),
): String {
    return mapper.encode(this, serializer)
}

@OptIn(ExperimentalSerializationApi::class)
public inline fun <reified T> String.deserializeFromJson(
    mapper: PasskeyJsonMapper,
    deserializer: DeserializationStrategy<T> = serializer(),
): T {
    return mapper.decode(this, deserializer)
}
