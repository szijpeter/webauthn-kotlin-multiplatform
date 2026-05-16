package dev.webauthn.serialization

import dev.webauthn.cbor.readUint16
import dev.webauthn.cbor.readUint32
import dev.webauthn.cbor.skipCborItem
import dev.webauthn.model.Aaguid
import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.CredentialId
import dev.webauthn.model.Origin
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

internal data class ParsedAuthenticatorData(
    val authenticatorData: AuthenticatorData,
    val attestedCredentialData: AttestedCredentialData?,
    val extensionDataBytes: ByteArray?,
)

private data class ParsedAttestedCredentialSection(
    val value: AttestedCredentialData,
    val nextOffset: Int,
)

@Serializable
private data class CollectedClientDataJsonDto(
    val type: String,
    val challenge: String,
    val origin: String,
    val crossOrigin: Boolean? = null,
)

@OptIn(ExperimentalSerializationApi::class)
private val attestationObjectCbor = Cbor {
    ignoreUnknownKeys = true
}

private val clientDataJsonParser = Json {
    ignoreUnknownKeys = true
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
private data class AttestationObjectCborDto(
    @SerialName("authData")
    @ByteString
    val authData: ByteArray? = null,
)

internal fun parseCollectedClientDataJson(
    bytes: ByteArray,
    field: String = "clientDataJSON",
): ValidationResult<CollectedClientData> {
    val text = runCatching {
        bytes.decodeToString(throwOnInvalidSequence = true)
    }.getOrElse {
        return ValidationResult.Invalid(
            listOf(
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "clientDataJSON must be valid UTF-8 JSON",
                ),
            ),
        )
    }

    val jsonObject = runCatching {
        clientDataJsonParser.parseToJsonElement(text).jsonObject
    }.getOrElse {
        return ValidationResult.Invalid(
            listOf(
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "clientDataJSON must be a valid JSON object",
                ),
            ),
        )
    }

    if (CLIENT_DATA_TYPE !in jsonObject) {
        return missingField("$field.$CLIENT_DATA_TYPE", CLIENT_DATA_TYPE)
    }
    if (CLIENT_DATA_CHALLENGE !in jsonObject) {
        return missingField("$field.$CLIENT_DATA_CHALLENGE", CLIENT_DATA_CHALLENGE)
    }
    if (CLIENT_DATA_ORIGIN !in jsonObject) {
        return missingField("$field.$CLIENT_DATA_ORIGIN", CLIENT_DATA_ORIGIN)
    }

    val dto = runCatching {
        clientDataJsonParser.decodeFromString<CollectedClientDataJsonDto>(text)
    }.getOrElse {
        return ValidationResult.Invalid(
            listOf(
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "clientDataJSON must use valid JSON field types",
                ),
            ),
        )
    }

    val parsedChallenge = when (val result = Challenge.parse(dto.challenge)) {
        is ValidationResult.Valid -> result.value
        is ValidationResult.Invalid -> return reprefixedInvalid(result.errors, "challenge", "$field.challenge")
    }
    val parsedOrigin = when (val result = Origin.parse(dto.origin)) {
        is ValidationResult.Valid -> result.value
        is ValidationResult.Invalid -> return reprefixedInvalid(result.errors, "origin", "$field.origin")
    }

    return ValidationResult.Valid(
        CollectedClientData(
            type = dto.type,
            challenge = parsedChallenge,
            origin = parsedOrigin,
            crossOrigin = dto.crossOrigin,
        ),
    )
}

@Suppress("MagicNumber")
internal fun parseAuthenticatorData(bytes: ByteArray, field: String): ValidationResult<ParsedAuthenticatorData> {
    if (bytes.size < 37) {
        return invalidFormat(field, "Authenticator data must be at least 37 bytes")
    }

    val rpIdHash = RpIdHash.fromBytes(bytes.copyOfRange(0, 32))
    val flags = bytes[32].toInt() and 0xFF
    val signCount = bytes.readUint32(33)
    var offset = 37

    val attestedCredentialData = if ((flags and FLAG_ATTESTED_CREDENTIAL_DATA) != 0) {
        when (val result = parseAttestedCredentialSection(bytes, offset, field)) {
            is ValidationResult.Valid -> {
                offset = result.value.nextOffset
                result.value.value
            }

            is ValidationResult.Invalid -> return result
        }
    } else {
        null
    }

    val extensionDataBytes = if ((flags and FLAG_EXTENSION_DATA_INCLUDED) != 0) {
        when (val result = parseExtensionData(bytes, offset, field)) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> return result
        }
    } else {
        if (offset != bytes.size) {
            return invalidFormat(field, "Unexpected trailing bytes after authenticator data")
        }
        null
    }

    return ValidationResult.Valid(
        ParsedAuthenticatorData(
            authenticatorData = AuthenticatorData(
                rpIdHash = rpIdHash,
                flags = flags,
                signCount = signCount,
            ),
            attestedCredentialData = attestedCredentialData,
            extensionDataBytes = extensionDataBytes,
        ),
    )
}

@Suppress("MagicNumber")
private fun parseAttestedCredentialSection(
    bytes: ByteArray,
    offset: Int,
    field: String,
): ValidationResult<ParsedAttestedCredentialSection> {
    if (bytes.size < offset + 16 + 2) {
        return invalidFormat(field, "Attested credential data is truncated")
    }

    val aaguid = Aaguid.fromBytes(bytes.copyOfRange(offset, offset + 16))
    var nextOffset = offset + 16
    val credentialIdLength = bytes.readUint16(nextOffset)
    nextOffset += 2
    if (bytes.size < nextOffset + credentialIdLength) {
        return invalidFormat(field, "Credential ID bytes are truncated")
    }

    val credentialId = bytes.copyOfRange(nextOffset, nextOffset + credentialIdLength)
    nextOffset += credentialIdLength
    if (!isCborMap(bytes, nextOffset)) {
        return invalidFormat(field, "COSE public key must be a CBOR map")
    }
    val coseEnd = skipCborItem(bytes, nextOffset) ?: return invalidFormat(field, "COSE public key is malformed")
    val cosePublicKey = CosePublicKey.fromBytes(bytes.copyOfRange(nextOffset, coseEnd))

    return ValidationResult.Valid(
        ParsedAttestedCredentialSection(
            value = AttestedCredentialData(
                aaguid = aaguid,
                credentialId = CredentialId.fromBytes(credentialId),
                cosePublicKey = cosePublicKey,
            ),
            nextOffset = coseEnd,
        ),
    )
}

private fun parseExtensionData(bytes: ByteArray, offset: Int, field: String): ValidationResult<ByteArray> {
    if (!isCborMap(bytes, offset)) {
        return invalidFormat(field, "Extension data must be a CBOR map")
    }
    val extensionEnd = skipCborItem(bytes, offset) ?: return invalidFormat(field, "Extension data is malformed")
    if (extensionEnd != bytes.size) {
        return invalidFormat(field, "Unexpected trailing bytes after extension data")
    }
    return ValidationResult.Valid(bytes.copyOfRange(offset, extensionEnd))
}

private fun isCborMap(bytes: ByteArray, offset: Int): Boolean {
    if (offset >= bytes.size) {
        return false
    }
    return ((bytes[offset].toInt() and UNSIGNED_BYTE_MASK) ushr CBOR_MAJOR_TYPE_SHIFT) == CBOR_MAP_MAJOR_TYPE
}

@OptIn(ExperimentalSerializationApi::class)
internal fun extractAuthDataFromAttestationObject(attestationObject: ByteArray): ByteArray? {
    val itemEnd = skipCborItem(attestationObject, 0) ?: return null
    if (itemEnd != attestationObject.size) {
        return null
    }
    return runCatching {
        attestationObjectCbor
            .decodeFromByteArray<AttestationObjectCborDto>(attestationObject)
            .authData
    }.getOrNull()
}

private fun <T> missingField(field: String, label: String): ValidationResult<T> {
    return ValidationResult.Invalid(
        listOf(
            WebAuthnValidationError.MissingValue(
                field = field,
                message = "clientDataJSON is missing $label",
            ),
        ),
    )
}

private fun <T> invalidFormat(field: String, message: String): ValidationResult<T> {
    return ValidationResult.Invalid(
        listOf(
            WebAuthnValidationError.InvalidFormat(
                field = field,
                message = message,
            ),
        ),
    )
}

private fun reprefixedInvalid(
    errors: List<WebAuthnValidationError>,
    source: String,
    target: String,
): ValidationResult.Invalid {
    return ValidationResult.Invalid(
        errors.map { error ->
            when (error) {
                is WebAuthnValidationError.InvalidFormat -> error.copy(field = error.field.replace(source, target))
                is WebAuthnValidationError.InvalidValue -> error.copy(field = error.field.replace(source, target))
                is WebAuthnValidationError.MissingValue -> error.copy(field = error.field.replace(source, target))
            }
        },
    )
}

internal const val FLAG_ATTESTED_CREDENTIAL_DATA: Int = 0x40
internal const val FLAG_EXTENSION_DATA_INCLUDED: Int = 0x80

private const val UNSIGNED_BYTE_MASK = 0xFF
private const val CBOR_MAJOR_TYPE_SHIFT = 5
private const val CBOR_MAP_MAJOR_TYPE = 5
private const val CLIENT_DATA_TYPE = "type"
private const val CLIENT_DATA_CHALLENGE = "challenge"
private const val CLIENT_DATA_ORIGIN = "origin"
