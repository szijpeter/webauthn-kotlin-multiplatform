package dev.webauthn.server.crypto

import dev.webauthn.model.Aaguid
import dev.webauthn.model.ImmutableBytes
import dev.webauthn.model.RpIdHash

internal fun rpIdHash(fill: Int = 0): RpIdHash = RpIdHash.fromBytes(ByteArray(32) { fill.toByte() })

internal fun aaguid(fill: Int = 0): Aaguid = Aaguid.fromBytes(ByteArray(16) { fill.toByte() })

internal fun immutableBytes(bytes: ByteArray): ImmutableBytes = ImmutableBytes.fromBytes(bytes)

internal fun immutableBytes(vararg value: Int): ImmutableBytes =
    ImmutableBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })

internal fun immutableList(vararg values: ByteArray): List<ImmutableBytes> = values.map(ImmutableBytes::fromBytes)
