package dev.webauthn.serialization

import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialDescriptor
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ResidentKeyRequirement
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.UserVerificationRequirement
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
public data class PublicKeyCredentialCreationOptionsDto(
    @SerialName("rp") public val rp: RpEntityDto,
    @SerialName("user") public val user: UserEntityDto,
    @SerialName("challenge") public val challenge: String,
    @SerialName("pubKeyCredParams") public val pubKeyCredParams: List<PublicKeyCredentialParametersDto>,
    @SerialName("timeout") public val timeoutMs: Long? = null,
    @SerialName("excludeCredentials") public val excludeCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    @SerialName("residentKey") public val residentKey: String = "preferred",
    @SerialName("userVerification") public val userVerification: String = "preferred",
)

@Serializable
public data class PublicKeyCredentialRequestOptionsDto(
    @SerialName("challenge") public val challenge: String,
    @SerialName("rpId") public val rpId: String,
    @SerialName("timeout") public val timeoutMs: Long? = null,
    @SerialName("allowCredentials") public val allowCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    @SerialName("userVerification") public val userVerification: String = "preferred",
)

@Serializable
public data class PublicKeyCredentialParametersDto(
    @SerialName("type") public val type: String,
    @SerialName("alg") public val alg: Int,
)

@Serializable
public data class PublicKeyCredentialDescriptorDto(
    @SerialName("type") public val type: String,
    @SerialName("id") public val id: String,
)

@Serializable
public data class RpEntityDto(
    @SerialName("id") public val id: String,
    @SerialName("name") public val name: String,
)

@Serializable
public data class UserEntityDto(
    @SerialName("id") public val id: String,
    @SerialName("name") public val name: String,
    @SerialName("displayName") public val displayName: String,
)

@Serializable
public data class RegistrationResponseDto(
    @SerialName("id") public val id: String,
    @SerialName("rawId") public val rawId: String,
    @SerialName("response") public val response: RegistrationResponsePayloadDto,
)

@Serializable
public data class RegistrationResponsePayloadDto(
    @SerialName("clientDataJSON") public val clientDataJson: String,
    @SerialName("attestationObject") public val attestationObject: String,
)

@Serializable
public data class AuthenticationResponseDto(
    @SerialName("id") public val id: String,
    @SerialName("rawId") public val rawId: String,
    @SerialName("response") public val response: AuthenticationResponsePayloadDto,
)

@Serializable
public data class AuthenticationResponsePayloadDto(
    @SerialName("clientDataJSON") public val clientDataJson: String,
    @SerialName("authenticatorData") public val authenticatorData: String,
    @SerialName("signature") public val signature: String,
    @SerialName("userHandle") public val userHandle: String? = null,
)

public object WebAuthnDtoMapper {
    public fun fromModel(value: PublicKeyCredentialCreationOptions): PublicKeyCredentialCreationOptionsDto {
        return PublicKeyCredentialCreationOptionsDto(
            rp = RpEntityDto(id = value.rp.id.value, name = value.rp.name),
            user = UserEntityDto(
                id = value.user.id.value.encoded(),
                name = value.user.name,
                displayName = value.user.displayName,
            ),
            challenge = value.challenge.value.encoded(),
            pubKeyCredParams = value.pubKeyCredParams.map {
                PublicKeyCredentialParametersDto(type = "public-key", alg = it.alg)
            },
            timeoutMs = value.timeoutMs,
            excludeCredentials = value.excludeCredentials.map {
                PublicKeyCredentialDescriptorDto(type = "public-key", id = it.id.value.encoded())
            },
            residentKey = value.residentKey.name.lowercase(),
            userVerification = value.userVerification.name.lowercase(),
        )
    }

    public fun toModel(value: PublicKeyCredentialCreationOptionsDto): ValidationResult<PublicKeyCredentialCreationOptions> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val rpId = RpId.parse(value.rp.id).fold(
            onValid = { it },
            onInvalid = { errors += it; null },
        )
        val userId = UserHandle.parse(value.user.id).fold(
            onValid = { it },
            onInvalid = { errors += it; null },
        )
        val challenge = Challenge.parse(value.challenge).fold(
            onValid = { it },
            onInvalid = { errors += it; null },
        )

        val params = value.pubKeyCredParams.mapNotNull { param ->
            if (param.type != "public-key") {
                errors += WebAuthnValidationError.InvalidValue(
                    field = "pubKeyCredParams.type",
                    message = "Only public-key is supported",
                )
                null
            } else {
                PublicKeyCredentialParameters(type = PublicKeyCredentialType.PUBLIC_KEY, alg = param.alg)
            }
        }

        val excludeCredentials = value.excludeCredentials.mapNotNull { descriptor ->
            val id = CredentialId.parse(descriptor.id).fold(
                onValid = { it },
                onInvalid = { err ->
                    errors += err
                    null
                },
            )
            if (id == null) {
                null
            } else {
                PublicKeyCredentialDescriptor(type = PublicKeyCredentialType.PUBLIC_KEY, id = id)
            }
        }

        if (rpId == null || userId == null || challenge == null || errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        val residentKey = ResidentKeyRequirement.entries.find { it.name.equals(value.residentKey, ignoreCase = true) }
            ?: ResidentKeyRequirement.PREFERRED
        val userVerification = UserVerificationRequirement.entries.find {
            it.name.equals(value.userVerification, ignoreCase = true)
        } ?: UserVerificationRequirement.PREFERRED

        return ValidationResult.Valid(
            PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(id = rpId, name = value.rp.name),
                user = PublicKeyCredentialUserEntity(id = userId, name = value.user.name, displayName = value.user.displayName),
                challenge = challenge,
                pubKeyCredParams = params,
                timeoutMs = value.timeoutMs,
                excludeCredentials = excludeCredentials,
                residentKey = residentKey,
                userVerification = userVerification,
            ),
        )
    }

    public fun fromModel(value: PublicKeyCredentialRequestOptions): PublicKeyCredentialRequestOptionsDto {
        return PublicKeyCredentialRequestOptionsDto(
            challenge = value.challenge.value.encoded(),
            rpId = value.rpId.value,
            timeoutMs = value.timeoutMs,
            allowCredentials = value.allowCredentials.map {
                PublicKeyCredentialDescriptorDto(type = "public-key", id = it.id.value.encoded())
            },
            userVerification = value.userVerification.name.lowercase(),
        )
    }

    public fun toModel(value: PublicKeyCredentialRequestOptionsDto): ValidationResult<PublicKeyCredentialRequestOptions> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val challenge = Challenge.parse(value.challenge).fold(
            onValid = { it },
            onInvalid = { errors += it; null },
        )
        val rpId = RpId.parse(value.rpId).fold(
            onValid = { it },
            onInvalid = { errors += it; null },
        )

        val allowCredentials = value.allowCredentials.mapNotNull { descriptor ->
            val id = CredentialId.parse(descriptor.id).fold(
                onValid = { it },
                onInvalid = { err ->
                    errors += err
                    null
                },
            )
            if (id == null) {
                null
            } else {
                PublicKeyCredentialDescriptor(type = PublicKeyCredentialType.PUBLIC_KEY, id = id)
            }
        }

        if (challenge == null || rpId == null || errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        val userVerification = UserVerificationRequirement.entries.find {
            it.name.equals(value.userVerification, ignoreCase = true)
        } ?: UserVerificationRequirement.PREFERRED

        return ValidationResult.Valid(
            PublicKeyCredentialRequestOptions(
                challenge = challenge,
                rpId = rpId,
                timeoutMs = value.timeoutMs,
                allowCredentials = allowCredentials,
                userVerification = userVerification,
            ),
        )
    }

    public fun toModel(value: RegistrationResponseDto): ValidationResult<RegistrationResponse> {
        val credentialId = CredentialId.parse(value.id)
        return when (credentialId) {
            is ValidationResult.Invalid -> credentialId
            is ValidationResult.Valid -> {
                val clientData = dev.webauthn.model.Base64UrlBytes.parse(value.response.clientDataJson, "clientDataJSON")
                val attestation = dev.webauthn.model.Base64UrlBytes.parse(value.response.attestationObject, "attestationObject")
                if (clientData is ValidationResult.Invalid) {
                    return clientData
                }
                if (attestation is ValidationResult.Invalid) {
                    return attestation
                }
                val authDataBytes = extractAuthDataFromAttestationObject((attestation as ValidationResult.Valid).value.bytes())
                if (authDataBytes == null) {
                    return ValidationResult.Invalid(
                        listOf(
                            WebAuthnValidationError.InvalidFormat(
                                field = "attestationObject",
                                message = "Attestation object does not contain a valid authData field",
                            ),
                        ),
                    )
                }
                val parsedAuthData = parseAuthenticatorData(authDataBytes, field = "attestationObject.authData")
                if (parsedAuthData is ValidationResult.Invalid) {
                    return parsedAuthData
                }
                val parsedAuthDataValue = (parsedAuthData as ValidationResult.Valid).value
                val attestedCredentialData = parsedAuthDataValue.attestedCredentialData
                    ?: return ValidationResult.Invalid(
                        listOf(
                            WebAuthnValidationError.InvalidFormat(
                                field = "attestationObject.authData",
                                message = "Attested credential data flag is not set or is malformed",
                            ),
                        ),
                    )
                ValidationResult.Valid(
                    RegistrationResponse(
                        credentialId = credentialId.value,
                        clientDataJson = (clientData as ValidationResult.Valid).value,
                        attestationObject = attestation.value,
                        rawAuthenticatorData = parsedAuthDataValue.authenticatorData,
                        attestedCredentialData = attestedCredentialData,
                    ),
                )
            }
        }
    }

    public fun toModel(value: AuthenticationResponseDto): ValidationResult<AuthenticationResponse> {
        val credentialId = CredentialId.parse(value.id)
        return when (credentialId) {
            is ValidationResult.Invalid -> credentialId
            is ValidationResult.Valid -> {
                val clientData = dev.webauthn.model.Base64UrlBytes.parse(value.response.clientDataJson, "clientDataJSON")
                val signature = dev.webauthn.model.Base64UrlBytes.parse(value.response.signature, "signature")
                val authenticatorData = dev.webauthn.model.Base64UrlBytes.parse(
                    value.response.authenticatorData,
                    "response.authenticatorData",
                )
                if (clientData is ValidationResult.Invalid) {
                    return clientData
                }
                if (signature is ValidationResult.Invalid) {
                    return signature
                }
                if (authenticatorData is ValidationResult.Invalid) {
                    return authenticatorData
                }
                val parsedAuthData = parseAuthenticatorData(
                    bytes = (authenticatorData as ValidationResult.Valid).value.bytes(),
                    field = "response.authenticatorData",
                )
                if (parsedAuthData is ValidationResult.Invalid) {
                    return parsedAuthData
                }

                val parsedUserHandle = when (val userHandle = value.response.userHandle) {
                    null -> null
                    else -> {
                        when (val parsed = UserHandle.parse(userHandle)) {
                            is ValidationResult.Invalid -> return parsed
                            is ValidationResult.Valid -> parsed.value
                        }
                    }
                }

                ValidationResult.Valid(
                    AuthenticationResponse(
                        credentialId = credentialId.value,
                        clientDataJson = (clientData as ValidationResult.Valid).value,
                        authenticatorData = (parsedAuthData as ValidationResult.Valid).value.authenticatorData,
                        signature = (signature as ValidationResult.Valid).value,
                        userHandle = parsedUserHandle,
                    ),
                )
            }
        }
    }
}

private data class ParsedAuthenticatorData(
    val authenticatorData: dev.webauthn.model.AuthenticatorData,
    val attestedCredentialData: AttestedCredentialData?,
)

private fun parseAuthenticatorData(bytes: ByteArray, field: String): ValidationResult<ParsedAuthenticatorData> {
    if (bytes.size < 37) {
        return ValidationResult.Invalid(
            listOf(
                WebAuthnValidationError.InvalidFormat(
                    field = field,
                    message = "Authenticator data must be at least 37 bytes",
                ),
            ),
        )
    }

    val rpIdHash = bytes.copyOfRange(0, 32)
    val flags = bytes[32].toInt() and 0xFF
    val signCount = bytes.readUint32(33)
    var offset = 37

    val attestedCredentialData = if ((flags and FLAG_ATTESTED_CREDENTIAL_DATA) != 0) {
        if (bytes.size < offset + 16 + 2) {
            return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidFormat(
                        field = field,
                        message = "Attested credential data is truncated",
                    ),
                ),
            )
        }
        val aaguid = bytes.copyOfRange(offset, offset + 16)
        offset += 16
        val credentialIdLength = bytes.readUint16(offset)
        offset += 2
        if (bytes.size < offset + credentialIdLength) {
            return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidFormat(
                        field = field,
                        message = "Credential ID bytes are truncated",
                    ),
                ),
            )
        }
        val credentialId = bytes.copyOfRange(offset, offset + credentialIdLength)
        offset += credentialIdLength
        val coseEnd = skipCborItem(bytes, offset)
            ?: return ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidFormat(
                        field = field,
                        message = "COSE public key is malformed",
                    ),
                ),
            )
        AttestedCredentialData(
            aaguid = aaguid,
            credentialId = CredentialId.fromBytes(credentialId),
            cosePublicKey = bytes.copyOfRange(offset, coseEnd),
        )
    } else {
        null
    }

    return ValidationResult.Valid(
        ParsedAuthenticatorData(
            authenticatorData = dev.webauthn.model.AuthenticatorData(
                rpIdHash = rpIdHash,
                flags = flags,
                signCount = signCount,
            ),
            attestedCredentialData = attestedCredentialData,
        ),
    )
}

private fun extractAuthDataFromAttestationObject(attestationObject: ByteArray): ByteArray? {
    var offset = 0
    val mapHeader = readCborHeader(attestationObject, offset) ?: return null
    if (mapHeader.majorType != MAJOR_MAP || mapHeader.length == null) {
        return null
    }
    offset = mapHeader.nextOffset

    repeat(mapHeader.length.toInt()) {
        val key = readCborText(attestationObject, offset) ?: return null
        offset = key.second
        if (key.first == "authData") {
            val authData = readCborByteString(attestationObject, offset) ?: return null
            offset = authData.second
            return authData.first
        }
        offset = skipCborItem(attestationObject, offset) ?: return null
    }
    return null
}

private data class CborHeader(
    val majorType: Int,
    val additionalInfo: Int,
    val length: Long?,
    val nextOffset: Int,
)

private fun readCborHeader(bytes: ByteArray, offset: Int): CborHeader? {
    if (offset >= bytes.size) return null
    val initial = bytes[offset].toInt() and 0xFF
    val majorType = (initial ushr 5) and 0x07
    val additionalInfo = initial and 0x1F
    val lengthResult = readCborLength(bytes, offset + 1, additionalInfo) ?: return null
    return CborHeader(
        majorType = majorType,
        additionalInfo = additionalInfo,
        length = lengthResult.first,
        nextOffset = lengthResult.second,
    )
}

private fun readCborLength(bytes: ByteArray, offset: Int, additionalInfo: Int): Pair<Long?, Int>? {
    return when {
        additionalInfo in 0..23 -> additionalInfo.toLong() to offset
        additionalInfo == 24 -> if (offset + 1 <= bytes.size) {
            (bytes[offset].toInt() and 0xFF).toLong() to (offset + 1)
        } else {
            null
        }

        additionalInfo == 25 -> if (offset + 2 <= bytes.size) {
            bytes.readUint16(offset).toLong() to (offset + 2)
        } else {
            null
        }

        additionalInfo == 26 -> if (offset + 4 <= bytes.size) {
            bytes.readUint32(offset) to (offset + 4)
        } else {
            null
        }

        additionalInfo == 27 -> if (offset + 8 <= bytes.size) {
            bytes.readInt64(offset) to (offset + 8)
        } else {
            null
        }

        additionalInfo == 31 -> null to offset
        else -> null
    }
}

private fun readCborText(bytes: ByteArray, offset: Int): Pair<String, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    if (header.majorType != MAJOR_TEXT || header.length == null) return null
    val length = header.length.toInt()
    if (length < 0 || header.nextOffset + length > bytes.size) return null
    val value = bytes.copyOfRange(header.nextOffset, header.nextOffset + length).decodeToString()
    return value to (header.nextOffset + length)
}

private fun readCborByteString(bytes: ByteArray, offset: Int): Pair<ByteArray, Int>? {
    val header = readCborHeader(bytes, offset) ?: return null
    if (header.majorType != MAJOR_BYTE_STRING || header.length == null) return null
    val length = header.length.toInt()
    if (length < 0 || header.nextOffset + length > bytes.size) return null
    return bytes.copyOfRange(header.nextOffset, header.nextOffset + length) to (header.nextOffset + length)
}

private fun skipCborItem(bytes: ByteArray, offset: Int): Int? {
    val header = readCborHeader(bytes, offset) ?: return null
    return when (header.majorType) {
        MAJOR_UNSIGNED_INT, MAJOR_NEGATIVE_INT -> header.nextOffset
        MAJOR_BYTE_STRING, MAJOR_TEXT -> {
            val length = header.length?.toInt() ?: return null
            val end = header.nextOffset + length
            if (end > bytes.size) return null
            end
        }

        MAJOR_ARRAY -> {
            val count = header.length?.toInt() ?: return null
            var next = header.nextOffset
            repeat(count) {
                next = skipCborItem(bytes, next) ?: return null
            }
            next
        }

        MAJOR_MAP -> {
            val count = header.length?.toInt() ?: return null
            var next = header.nextOffset
            repeat(count) {
                next = skipCborItem(bytes, next) ?: return null
                next = skipCborItem(bytes, next) ?: return null
            }
            next
        }

        MAJOR_TAG -> skipCborItem(bytes, header.nextOffset)
        MAJOR_SIMPLE_FLOAT -> {
            when (header.additionalInfo) {
                in 0..23 -> header.nextOffset
                24 -> if (header.nextOffset + 1 <= bytes.size) header.nextOffset + 1 else null
                25 -> if (header.nextOffset + 2 <= bytes.size) header.nextOffset + 2 else null
                26 -> if (header.nextOffset + 4 <= bytes.size) header.nextOffset + 4 else null
                27 -> if (header.nextOffset + 8 <= bytes.size) header.nextOffset + 8 else null
                else -> null
            }
        }

        else -> null
    }
}

private fun ByteArray.readUint16(offset: Int): Int {
    return ((this[offset].toInt() and 0xFF) shl 8) or
        (this[offset + 1].toInt() and 0xFF)
}

private fun ByteArray.readUint32(offset: Int): Long {
    return ((this[offset].toLong() and 0xFF) shl 24) or
        ((this[offset + 1].toLong() and 0xFF) shl 16) or
        ((this[offset + 2].toLong() and 0xFF) shl 8) or
        (this[offset + 3].toLong() and 0xFF)
}

private fun ByteArray.readInt64(offset: Int): Long {
    return ((this[offset].toLong() and 0xFF) shl 56) or
        ((this[offset + 1].toLong() and 0xFF) shl 48) or
        ((this[offset + 2].toLong() and 0xFF) shl 40) or
        ((this[offset + 3].toLong() and 0xFF) shl 32) or
        ((this[offset + 4].toLong() and 0xFF) shl 24) or
        ((this[offset + 5].toLong() and 0xFF) shl 16) or
        ((this[offset + 6].toLong() and 0xFF) shl 8) or
        (this[offset + 7].toLong() and 0xFF)
}

private const val FLAG_ATTESTED_CREDENTIAL_DATA: Int = 0x40
private const val MAJOR_UNSIGNED_INT: Int = 0
private const val MAJOR_NEGATIVE_INT: Int = 1
private const val MAJOR_BYTE_STRING: Int = 2
private const val MAJOR_TEXT: Int = 3
private const val MAJOR_ARRAY: Int = 4
private const val MAJOR_MAP: Int = 5
private const val MAJOR_TAG: Int = 6
private const val MAJOR_SIMPLE_FLOAT: Int = 7

private inline fun <T, R> ValidationResult<T>.fold(
    onValid: (T) -> R,
    onInvalid: (List<WebAuthnValidationError>) -> R,
): R {
    return when (this) {
        is ValidationResult.Valid -> onValid(value)
        is ValidationResult.Invalid -> onInvalid(errors)
    }
}
