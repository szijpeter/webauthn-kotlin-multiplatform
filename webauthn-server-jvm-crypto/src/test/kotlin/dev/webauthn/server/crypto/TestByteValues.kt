package dev.webauthn.server.crypto

import dev.webauthn.model.Aaguid
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.RpIdHash

internal fun rpIdHash(fill: Int = 0): RpIdHash = RpIdHash.fromBytes(ByteArray(32) { fill.toByte() })

internal fun aaguid(fill: Int = 0): Aaguid = Aaguid.fromBytes(ByteArray(16) { fill.toByte() })

internal fun base64UrlBytes(bytes: ByteArray): Base64UrlBytes = Base64UrlBytes.fromBytes(bytes)

internal fun cosePublicKey(bytes: ByteArray): CosePublicKey = CosePublicKey.fromBytes(bytes)

internal fun base64UrlBytes(vararg value: Int): Base64UrlBytes =
    Base64UrlBytes.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })

internal fun cosePublicKey(vararg value: Int): CosePublicKey =
    CosePublicKey.fromBytes(ByteArray(value.size) { index -> value[index].toByte() })

internal fun base64UrlList(vararg values: ByteArray): List<Base64UrlBytes> = values.map(Base64UrlBytes::fromBytes)
