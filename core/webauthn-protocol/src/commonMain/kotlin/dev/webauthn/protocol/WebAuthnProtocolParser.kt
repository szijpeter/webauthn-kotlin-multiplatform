package dev.webauthn.protocol

import dev.webauthn.cbor.MAJOR_MAP
import dev.webauthn.cbor.readCborBytes
import dev.webauthn.cbor.readCborHeader
import dev.webauthn.cbor.readCborText
import dev.webauthn.cbor.readUint16
import dev.webauthn.cbor.readUint32
import dev.webauthn.cbor.skipCborItem
import dev.webauthn.model.Aaguid
import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticatorData
import dev.webauthn.model.CosePublicKey
import dev.webauthn.model.CredentialId
import dev.webauthn.model.RpIdHash
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError

/** Parsed authenticator-data values, separated from their original byte representation. */
public data class ParsedAuthenticatorData(
    public val authenticatorData: AuthenticatorData,
    public val attestedCredentialData: AttestedCredentialData?,
    public val extensionDataBytes: ByteArray?,
)

/** Strict, serialization-library-neutral WebAuthn binary protocol parser. */
@MustUseReturnValues
public object WebAuthnProtocolParser {
    /** Parses an authenticator-data byte sequence according to WebAuthn L3 §6.1. */
    @Suppress("MagicNumber")
    public fun parseAuthenticatorData(
        bytes: ByteArray,
        field: String = "authenticatorData",
    ): ValidationResult<ParsedAuthenticatorData> {
        if (bytes.size < AUTHENTICATOR_DATA_MINIMUM_LENGTH) {
            return invalidFormat(field, "Authenticator data must be at least 37 bytes")
        }

        val rpIdHash = RpIdHash.fromBytes(bytes.copyOfRange(0, RP_ID_HASH_LENGTH))
        val flags = bytes[AUTHENTICATOR_DATA_FLAGS_OFFSET].toInt() and UNSIGNED_BYTE_MASK
        val signCount = bytes.readUint32(AUTHENTICATOR_DATA_SIGN_COUNT_OFFSET)
        var offset = AUTHENTICATOR_DATA_MINIMUM_LENGTH

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

    /** Extracts the `authData` byte string from a structurally valid attestation object. */
    public fun extractAuthenticatorData(
        attestationObject: ByteArray,
        field: String = "attestationObject",
    ): ValidationResult<ByteArray> {
        val objectEnd = skipCborItem(attestationObject, 0)
            ?: return invalidFormat(field, "Attestation object must be a valid CBOR item")
        if (objectEnd != attestationObject.size) {
            return invalidFormat(field, "Attestation object must not contain trailing bytes")
        }

        val header = readCborHeader(attestationObject, 0)
            ?: return invalidFormat(field, "Attestation object must be a CBOR map")
        val entryCount = header.length
        if (header.majorType != MAJOR_MAP || entryCount == null || entryCount > Int.MAX_VALUE.toLong()) {
            return invalidFormat(field, "Attestation object must be a definite-length CBOR map")
        }

        var offset = header.nextOffset
        var authData: ByteArray? = null
        repeat(entryCount.toInt()) {
            val key = readCborText(attestationObject, offset)
                ?: return invalidFormat(field, "Attestation object keys must be text strings")
            offset = key.second
            if (key.first == AUTH_DATA_KEY) {
                if (authData != null) {
                    return invalidFormat(field, "Attestation object must not duplicate authData")
                }
                val value = readCborBytes(attestationObject, offset)
                    ?: return invalidFormat("$field.authData", "authData must be a CBOR byte string")
                authData = value.first
                offset = value.second
            } else {
                offset = skipCborItem(attestationObject, offset)
                    ?: return invalidFormat(field, "Attestation object contains malformed CBOR")
            }
        }

        return authData?.let { ValidationResult.Valid(it) }
            ?: invalidFormat(field, "Attestation object does not contain authData")
    }
}

private data class ParsedAttestedCredentialSection(
    val value: AttestedCredentialData,
    val nextOffset: Int,
)

@Suppress("MagicNumber")
private fun parseAttestedCredentialSection(
    bytes: ByteArray,
    offset: Int,
    field: String,
): ValidationResult<ParsedAttestedCredentialSection> {
    if (bytes.size < offset + AAGUID_LENGTH + CREDENTIAL_ID_LENGTH_FIELD_SIZE) {
        return invalidFormat(field, "Attested credential data is truncated")
    }

    val aaguid = Aaguid.fromBytes(bytes.copyOfRange(offset, offset + AAGUID_LENGTH))
    var nextOffset = offset + AAGUID_LENGTH
    val credentialIdLength = bytes.readUint16(nextOffset)
    nextOffset += CREDENTIAL_ID_LENGTH_FIELD_SIZE
    if (bytes.size < nextOffset + credentialIdLength) {
        return invalidFormat(field, "Credential ID bytes are truncated")
    }
    val credentialId = bytes.copyOfRange(nextOffset, nextOffset + credentialIdLength)
    nextOffset += credentialIdLength
    val coseEnd = skipCborItem(bytes, nextOffset)
        ?: return invalidFormat(field, "COSE public key is malformed")
    val coseHeader = readCborHeader(bytes, nextOffset)
        ?: return invalidFormat(field, "COSE public key is malformed")
    if (coseHeader.majorType != MAJOR_MAP) {
        return invalidFormat(field, "COSE public key must be a CBOR map")
    }

    return ValidationResult.Valid(
        ParsedAttestedCredentialSection(
            value = AttestedCredentialData(
                aaguid = aaguid,
                credentialId = CredentialId.fromBytes(credentialId),
                cosePublicKey = CosePublicKey.fromBytes(bytes.copyOfRange(nextOffset, coseEnd)),
            ),
            nextOffset = coseEnd,
        ),
    )
}

private fun parseExtensionData(bytes: ByteArray, offset: Int, field: String): ValidationResult<ByteArray> {
    val extensionEnd = skipCborItem(bytes, offset)
        ?: return invalidFormat(field, "Extension data is malformed")
    val extensionHeader = readCborHeader(bytes, offset)
        ?: return invalidFormat(field, "Extension data is malformed")
    if (extensionHeader.majorType != MAJOR_MAP) {
        return invalidFormat(field, "Extension data must be a CBOR map")
    }
    if (extensionEnd != bytes.size) {
        return invalidFormat(field, "Unexpected trailing bytes after extension data")
    }
    return ValidationResult.Valid(bytes.copyOfRange(offset, extensionEnd))
}

private fun <T> invalidFormat(field: String, message: String): ValidationResult<T> {
    return ValidationResult.Invalid(
        [WebAuthnValidationError.InvalidFormat(field = field, message = message)],
    )
}

private const val AUTHENTICATOR_DATA_MINIMUM_LENGTH: Int = 37
private const val RP_ID_HASH_LENGTH: Int = 32
private const val AUTHENTICATOR_DATA_FLAGS_OFFSET: Int = 32
private const val AUTHENTICATOR_DATA_SIGN_COUNT_OFFSET: Int = 33
private const val AAGUID_LENGTH: Int = 16
private const val CREDENTIAL_ID_LENGTH_FIELD_SIZE: Int = 2
private const val UNSIGNED_BYTE_MASK: Int = 0xFF
private const val FLAG_ATTESTED_CREDENTIAL_DATA: Int = 0x40
private const val FLAG_EXTENSION_DATA_INCLUDED: Int = 0x80
private const val AUTH_DATA_KEY: String = "authData"
