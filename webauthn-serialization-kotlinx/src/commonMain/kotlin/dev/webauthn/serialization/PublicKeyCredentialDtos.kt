package dev.webauthn.serialization

import dev.webauthn.internal.cbor.skipCborItem
import dev.webauthn.internal.cbor.readUint16
import dev.webauthn.internal.cbor.readUint32
import dev.webauthn.model.AttestedCredentialData
import dev.webauthn.model.AttestationConveyancePreference
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.AuthenticatorAttachment
import dev.webauthn.model.AuthenticatorTransport
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
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray

/**
 * DTO for the /.well-known/webauthn file used by the Related Origins extension.
 */
@Serializable
public data class RelatedOriginsDto(
    @SerialName("origins") public val origins: List<String>,
)

@Serializable
public data class AuthenticatorSelectionCriteriaDto(
    @SerialName("authenticatorAttachment") public val authenticatorAttachment: String? = null,
    @SerialName("residentKey") public val residentKey: String? = null,
    @SerialName("requireResidentKey") public val requireResidentKey: Boolean? = null,
    @SerialName("userVerification") public val userVerification: String? = null,
)

@Serializable
public data class PublicKeyCredentialCreationOptionsDto(
    @SerialName("rp") public val rp: RpEntityDto,
    @SerialName("user") public val user: UserEntityDto,
    @SerialName("challenge") public val challenge: String,
    @SerialName("pubKeyCredParams") public val pubKeyCredParams: List<PublicKeyCredentialParametersDto>,
    @SerialName("timeout") public val timeoutMs: Long? = null,
    @SerialName("excludeCredentials") public val excludeCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    @SerialName("authenticatorSelection") public val authenticatorSelection: AuthenticatorSelectionCriteriaDto? = null,
    @SerialName("attestation") public val attestation: String? = null,
    @SerialName("extensions") public val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
public data class PublicKeyCredentialRequestOptionsDto(
    @SerialName("challenge") public val challenge: String,
    @SerialName("rpId") public val rpId: String,
    @SerialName("timeout") public val timeoutMs: Long? = null,
    @SerialName("allowCredentials") public val allowCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    @SerialName("userVerification") public val userVerification: String = "preferred",
    @SerialName("extensions") public val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
public data class AuthenticationExtensionsClientInputsDto(
    @SerialName("prf") public val prf: PrfExtensionInputDto? = null,
    @SerialName("largeBlob") public val largeBlob: LargeBlobExtensionInputDto? = null,
    @SerialName("relatedOrigins") public val relatedOrigins: List<String>? = null,
)

@Serializable
public data class PrfExtensionInputDto(
    @SerialName("eval") public val eval: PrfValuesDto? = null,
    @SerialName("evalByCredential") public val evalByCredential: Map<String, PrfValuesDto>? = null,
)

@Serializable
public data class LargeBlobExtensionInputDto(
    @SerialName("support") public val support: String? = null,
    @SerialName("read") public val read: Boolean? = null,
    @SerialName("write") public val write: String? = null,
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
    @SerialName("transports") public val transports: List<String>? = null,
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
    @SerialName("authenticatorAttachment") public val authenticatorAttachment: String? = null,
    @SerialName("clientExtensionResults") public val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
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
    @SerialName("authenticatorAttachment") public val authenticatorAttachment: String? = null,
    @SerialName("clientExtensionResults") public val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
)

@Serializable
public data class AuthenticationResponsePayloadDto(
    @SerialName("clientDataJSON") public val clientDataJson: String,
    @SerialName("authenticatorData") public val authenticatorData: String,
    @SerialName("signature") public val signature: String,
    @SerialName("userHandle") public val userHandle: String? = null,
)

@Serializable
public data class AuthenticationExtensionsClientOutputsDto(
    @SerialName("prf") public val prf: PrfExtensionOutputDto? = null,
    @SerialName("largeBlob") public val largeBlob: LargeBlobExtensionOutputDto? = null,
)

@Serializable
public data class PrfExtensionOutputDto(
    @SerialName("enabled") public val enabled: Boolean? = null,
    @SerialName("results") public val results: PrfValuesDto? = null,
)

@Serializable
public data class PrfValuesDto(
    @SerialName("first") public val first: String,
    @SerialName("second") public val second: String? = null,
)

@Serializable
public data class LargeBlobExtensionOutputDto(
    @SerialName("supported") public val supported: Boolean? = null,
    @SerialName("blob") public val blob: String? = null,
    @SerialName("written") public val written: Boolean? = null,
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
                PublicKeyCredentialDescriptorDto(
                    type = "public-key",
                    id = it.id.value.encoded(),
                    transports = it.transports.map { transport -> transport.toDtoValue() }.ifEmpty { null },
                )
            },
            authenticatorSelection = AuthenticatorSelectionCriteriaDto(
                authenticatorAttachment = value.authenticatorAttachment?.toDtoValue(),
                residentKey = value.residentKey.name.lowercase(),
                requireResidentKey = value.residentKey == ResidentKeyRequirement.REQUIRED,
                userVerification = value.userVerification.name.lowercase(),
            ),
            attestation = value.attestation?.toDtoValue(),
            extensions = value.extensions?.let(::fromModel),
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
            val transports = descriptor.transports.orEmpty().mapIndexedNotNull { index, encodedTransport ->
                when (val parsed = parseAuthenticatorTransport(encodedTransport, "excludeCredentials[$index].transports")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            if (id == null) {
                null
            } else {
                PublicKeyCredentialDescriptor(type = PublicKeyCredentialType.PUBLIC_KEY, id = id, transports = transports)
            }
        }

        if (rpId == null || userId == null || challenge == null || errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        val residentKey = value.authenticatorSelection?.residentKey?.let { rk ->
            ResidentKeyRequirement.entries.find { it.name.equals(rk, ignoreCase = true) }
        } ?: if (value.authenticatorSelection?.requireResidentKey == true) {
            ResidentKeyRequirement.REQUIRED
        } else {
            ResidentKeyRequirement.PREFERRED
        }
        val userVerification = value.authenticatorSelection?.userVerification?.let { uv ->
            UserVerificationRequirement.entries.find {
                it.name.equals(uv, ignoreCase = true)
            }
        } ?: UserVerificationRequirement.PREFERRED
        val authenticatorAttachment = value.authenticatorSelection?.authenticatorAttachment?.let {
            when (val parsed = parseAuthenticatorAttachment(it, "authenticatorAttachment")) {
                is ValidationResult.Valid -> parsed.value
                is ValidationResult.Invalid -> {
                    errors += parsed.errors
                    null
                }
            }
        }
        val attestation = value.attestation?.let {
            when (val parsed = parseAttestationConveyancePreference(it, "attestation")) {
                is ValidationResult.Valid -> parsed.value
                is ValidationResult.Invalid -> {
                    errors += parsed.errors
                    null
                }
            }
        }
        val extensions = value.extensions?.let {
            when (val parsed = toModelValidated(it, fieldPrefix = "extensions")) {
                is ValidationResult.Valid -> parsed.value
                is ValidationResult.Invalid -> {
                    errors += parsed.errors
                    null
                }
            }
        }

        if (errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        return ValidationResult.Valid(
            PublicKeyCredentialCreationOptions(
                rp = PublicKeyCredentialRpEntity(id = rpId, name = value.rp.name),
                user = PublicKeyCredentialUserEntity(id = userId, name = value.user.name, displayName = value.user.displayName),
                challenge = challenge,
                pubKeyCredParams = params,
                timeoutMs = value.timeoutMs,
                excludeCredentials = excludeCredentials,
                authenticatorAttachment = authenticatorAttachment,
                residentKey = residentKey,
                userVerification = userVerification,
                attestation = attestation,
                extensions = extensions,
            ),
        )
    }

    public fun fromModel(value: PublicKeyCredentialRequestOptions): PublicKeyCredentialRequestOptionsDto {
        return PublicKeyCredentialRequestOptionsDto(
            challenge = value.challenge.value.encoded(),
            rpId = value.rpId.value,
            timeoutMs = value.timeoutMs,
            allowCredentials = value.allowCredentials.map {
                PublicKeyCredentialDescriptorDto(
                    type = "public-key",
                    id = it.id.value.encoded(),
                    transports = it.transports.map { transport -> transport.toDtoValue() }.ifEmpty { null },
                )
            },
            userVerification = value.userVerification.name.lowercase(),
            extensions = value.extensions?.let(::fromModel),
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
            val transports = descriptor.transports.orEmpty().mapIndexedNotNull { index, encodedTransport ->
                when (val parsed = parseAuthenticatorTransport(encodedTransport, "allowCredentials[$index].transports")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            if (id == null) {
                null
            } else {
                PublicKeyCredentialDescriptor(type = PublicKeyCredentialType.PUBLIC_KEY, id = id, transports = transports)
            }
        }

        if (challenge == null || rpId == null || errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        val userVerification = UserVerificationRequirement.entries.find {
            it.name.equals(value.userVerification, ignoreCase = true)
        } ?: UserVerificationRequirement.PREFERRED
        val extensions = value.extensions?.let {
            when (val parsed = toModelValidated(it, fieldPrefix = "extensions")) {
                is ValidationResult.Valid -> parsed.value
                is ValidationResult.Invalid -> {
                    errors += parsed.errors
                    null
                }
            }
        }

        if (errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        return ValidationResult.Valid(
            PublicKeyCredentialRequestOptions(
                challenge = challenge,
                rpId = rpId,
                timeoutMs = value.timeoutMs,
                allowCredentials = allowCredentials,
                userVerification = userVerification,
                extensions = extensions,
            ),
        )
    }

    public fun toModel(value: RegistrationResponseDto): ValidationResult<RegistrationResponse> {
        val credentialId = CredentialId.parse(value.rawId)
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
                val extensions = value.clientExtensionResults?.let {
                    when (val parsed = toModelValidated(it, fieldPrefix = "clientExtensionResults")) {
                        is ValidationResult.Valid -> parsed.value
                        is ValidationResult.Invalid -> return ValidationResult.Invalid(parsed.errors)
                    }
                }
                val authenticatorAttachment = value.authenticatorAttachment?.let { encodedAttachment ->
                    when (val parsed = parseAuthenticatorAttachment(encodedAttachment, "authenticatorAttachment")) {
                        is ValidationResult.Valid -> parsed.value
                        is ValidationResult.Invalid -> return ValidationResult.Invalid(parsed.errors)
                    }
                }
                ValidationResult.Valid(
                    RegistrationResponse(
                        credentialId = credentialId.value,
                        clientDataJson = (clientData as ValidationResult.Valid).value,
                        attestationObject = attestation.value,
                        rawAuthenticatorData = parsedAuthDataValue.authenticatorData,
                        attestedCredentialData = attestedCredentialData,
                        authenticatorAttachment = authenticatorAttachment,
                        extensions = extensions,
                    ),
                )
            }
        }
    }

    public fun fromModel(value: RegistrationResponse): RegistrationResponseDto {
        val credentialId = value.attestedCredentialData.credentialId
        return RegistrationResponseDto(
            id = credentialId.value.encoded(),
            rawId = credentialId.value.encoded(),
            response = RegistrationResponsePayloadDto(
                clientDataJson = value.clientDataJson.encoded(),
                attestationObject = value.attestationObject.encoded(),
            ),
            authenticatorAttachment = value.authenticatorAttachment?.toDtoValue(),
            clientExtensionResults = value.extensions?.let(::fromModel),
        )
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
                val clientDataValue = (clientData as ValidationResult.Valid).value
                val signatureValue = (signature as ValidationResult.Valid).value
                val authenticatorDataValue = (authenticatorData as ValidationResult.Valid).value
                val parsedAuthData = parseAuthenticatorData(
                    bytes = authenticatorDataValue.bytes(),
                    field = "response.authenticatorData",
                )
                if (parsedAuthData is ValidationResult.Invalid) {
                    return parsedAuthData
                }
                val parsedAuthDataValue = (parsedAuthData as ValidationResult.Valid).value

                val parsedUserHandle = when (val userHandle = value.response.userHandle) {
                    null -> null
                    else -> {
                        when (val parsed = UserHandle.parse(userHandle)) {
                            is ValidationResult.Invalid -> return parsed
                            is ValidationResult.Valid -> parsed.value
                        }
                    }
                }
                val extensions = value.clientExtensionResults?.let {
                    when (val parsed = toModelValidated(it, fieldPrefix = "clientExtensionResults")) {
                        is ValidationResult.Valid -> parsed.value
                        is ValidationResult.Invalid -> return ValidationResult.Invalid(parsed.errors)
                    }
                }
                val authenticatorAttachment = value.authenticatorAttachment?.let { encodedAttachment ->
                    when (val parsed = parseAuthenticatorAttachment(encodedAttachment, "authenticatorAttachment")) {
                        is ValidationResult.Valid -> parsed.value
                        is ValidationResult.Invalid -> return ValidationResult.Invalid(parsed.errors)
                    }
                }

                ValidationResult.Valid(
                    AuthenticationResponse(
                        credentialId = credentialId.value,
                        clientDataJson = clientDataValue,
                        rawAuthenticatorData = authenticatorDataValue,
                        authenticatorData = parsedAuthDataValue.authenticatorData,
                        signature = signatureValue,
                        userHandle = parsedUserHandle,
                        authenticatorAttachment = authenticatorAttachment,
                        extensions = extensions,
                    ),
                )
            }
        }
    }

    public fun fromModel(value: AuthenticationResponse): AuthenticationResponseDto {
        return AuthenticationResponseDto(
            id = value.credentialId.value.encoded(),
            rawId = value.credentialId.value.encoded(),
            response = AuthenticationResponsePayloadDto(
                clientDataJson = value.clientDataJson.encoded(),
                authenticatorData = value.rawAuthenticatorData.encoded(),
                signature = value.signature.encoded(),
                userHandle = value.userHandle?.value?.encoded(),
            ),
            authenticatorAttachment = value.authenticatorAttachment?.toDtoValue(),
            clientExtensionResults = value.extensions?.let(::fromModel),
        )
    }

    // --- Extension Mapping Helpers ---

    public fun fromModel(value: dev.webauthn.model.AuthenticationExtensionsClientInputs): AuthenticationExtensionsClientInputsDto {
        return AuthenticationExtensionsClientInputsDto(
            prf = value.prf?.let { prf ->
                PrfExtensionInputDto(
                    eval = prf.eval?.let(::fromModel),
                    evalByCredential = prf.evalByCredential?.mapValues { fromModel(it.value) }
                )
            },
            largeBlob = value.largeBlob?.let { lb ->
                LargeBlobExtensionInputDto(
                    support = lb.support?.name?.lowercase(),
                    read = lb.read,
                    write = lb.write?.toBase64Url()
                )
            },
            relatedOrigins = value.relatedOrigins
        )
    }

    @Deprecated(
        message = "Use toModelValidated(AuthenticationExtensionsClientInputsDto) for error-safe parsing.",
        replaceWith = ReplaceWith("toModelValidated(value).getOrThrow()"),
    )
    public fun toModel(value: AuthenticationExtensionsClientInputsDto): dev.webauthn.model.AuthenticationExtensionsClientInputs {
        return toModelValidated(value).fold(
            onValid = { it },
            onInvalid = { errors ->
                throw IllegalArgumentException(errors.joinToString("; ") { "${it.field}: ${it.message}" })
            },
        )
    }

    public fun fromModel(value: dev.webauthn.model.AuthenticationExtensionsClientOutputs): AuthenticationExtensionsClientOutputsDto {
        return AuthenticationExtensionsClientOutputsDto(
            prf = value.prf?.let { prf ->
                PrfExtensionOutputDto(
                    enabled = prf.enabled,
                    results = prf.results?.let(::fromModel)
                )
            },
            largeBlob = value.largeBlob?.let { lb ->
                LargeBlobExtensionOutputDto(
                    supported = lb.supported,
                    blob = lb.blob?.toBase64Url(),
                    written = lb.written
                )
            }
        )
    }

    @Deprecated(
        message = "Use toModelValidated(AuthenticationExtensionsClientOutputsDto) for error-safe parsing.",
        replaceWith = ReplaceWith("toModelValidated(value).getOrThrow()"),
    )
    public fun toModel(value: AuthenticationExtensionsClientOutputsDto): dev.webauthn.model.AuthenticationExtensionsClientOutputs {
        return toModelValidated(value).fold(
            onValid = { it },
            onInvalid = { errors ->
                throw IllegalArgumentException(errors.joinToString("; ") { "${it.field}: ${it.message}" })
            },
        )
    }

    private fun fromModel(value: dev.webauthn.model.AuthenticationExtensionsPRFValues): PrfValuesDto {
        return PrfValuesDto(
            first = value.first.toBase64Url(),
            second = value.second?.toBase64Url()
        )
    }

    public fun toModelValidated(
        value: AuthenticationExtensionsClientInputsDto,
        fieldPrefix: String = "extensions",
    ): ValidationResult<dev.webauthn.model.AuthenticationExtensionsClientInputs> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val prf = value.prf?.let { prf ->
            val eval = prf.eval?.let { prfValues ->
                when (val parsed = toModelValidated(prfValues, "$fieldPrefix.prf.eval")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            val evalByCredential = prf.evalByCredential?.let { evalMap ->
                val parsed = mutableMapOf<String, dev.webauthn.model.AuthenticationExtensionsPRFValues>()
                for ((credentialId, prfValues) in evalMap) {
                    when (val parsedValue = toModelValidated(prfValues, "$fieldPrefix.prf.evalByCredential.$credentialId")) {
                        is ValidationResult.Valid -> parsed[credentialId] = parsedValue.value
                        is ValidationResult.Invalid -> errors += parsedValue.errors
                    }
                }
                parsed
            }
            dev.webauthn.model.PrfExtensionInput(eval = eval, evalByCredential = evalByCredential)
        }

        val largeBlob = value.largeBlob?.let { lb ->
            val support = lb.support?.let {
                val parsedSupport = dev.webauthn.model.LargeBlobExtensionInput.LargeBlobSupport.entries
                    .find { entry -> entry.name.equals(it, ignoreCase = true) }
                if (parsedSupport == null) {
                    errors += WebAuthnValidationError.InvalidValue(
                        field = "$fieldPrefix.largeBlob.support",
                        message = "Unknown support value: $it",
                    )
                }
                parsedSupport
            }
            val write = lb.write?.let {
                when (val parsed = parseBase64Url(it, "$fieldPrefix.largeBlob.write")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            dev.webauthn.model.LargeBlobExtensionInput(
                support = support,
                read = lb.read,
                write = write,
            )
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(
                dev.webauthn.model.AuthenticationExtensionsClientInputs(
                    prf = prf,
                    largeBlob = largeBlob,
                    relatedOrigins = value.relatedOrigins,
                ),
            )
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    public fun toModelValidated(
        value: AuthenticationExtensionsClientOutputsDto,
        fieldPrefix: String = "clientExtensionResults",
    ): ValidationResult<dev.webauthn.model.AuthenticationExtensionsClientOutputs> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val prf = value.prf?.let { prf ->
            val results = prf.results?.let { prfValues ->
                when (val parsed = toModelValidated(prfValues, "$fieldPrefix.prf.results")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            dev.webauthn.model.PrfExtensionOutput(enabled = prf.enabled, results = results)
        }

        val largeBlob = value.largeBlob?.let { lb ->
            val blob = lb.blob?.let {
                when (val parsed = parseBase64Url(it, "$fieldPrefix.largeBlob.blob")) {
                    is ValidationResult.Valid -> parsed.value
                    is ValidationResult.Invalid -> {
                        errors += parsed.errors
                        null
                    }
                }
            }
            dev.webauthn.model.LargeBlobExtensionOutput(
                supported = lb.supported,
                blob = blob,
                written = lb.written,
            )
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid(
                dev.webauthn.model.AuthenticationExtensionsClientOutputs(
                    prf = prf,
                    largeBlob = largeBlob,
                ),
            )
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    private fun toModelValidated(
        value: PrfValuesDto,
        fieldPrefix: String,
    ): ValidationResult<dev.webauthn.model.AuthenticationExtensionsPRFValues> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val first = when (val parsed = parseBase64Url(value.first, "$fieldPrefix.first")) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                errors += parsed.errors
                null
            }
        }

        val second = value.second?.let {
            when (val parsed = parseBase64Url(it, "$fieldPrefix.second")) {
                is ValidationResult.Valid -> parsed.value
                is ValidationResult.Invalid -> {
                    errors += parsed.errors
                    null
                }
            }
        }

        return if (first != null && errors.isEmpty()) {
            ValidationResult.Valid(
                dev.webauthn.model.AuthenticationExtensionsPRFValues(
                    first = first,
                    second = second,
                ),
            )
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    private fun parseBase64Url(
        value: String,
        field: String,
    ): ValidationResult<dev.webauthn.model.Base64UrlBytes> {
        return dev.webauthn.model.Base64UrlBytes.parse(value, field)
    }

    private fun AuthenticatorAttachment.toDtoValue(): String {
        return when (this) {
            AuthenticatorAttachment.PLATFORM -> "platform"
            AuthenticatorAttachment.CROSS_PLATFORM -> "cross-platform"
        }
    }

    private fun AttestationConveyancePreference.toDtoValue(): String = name.lowercase()

    private fun AuthenticatorTransport.toDtoValue(): String {
        return when (this) {
            AuthenticatorTransport.USB -> "usb"
            AuthenticatorTransport.NFC -> "nfc"
            AuthenticatorTransport.BLE -> "ble"
            AuthenticatorTransport.SMART_CARD -> "smart-card"
            AuthenticatorTransport.HYBRID -> "hybrid"
            AuthenticatorTransport.INTERNAL -> "internal"
        }
    }

    private fun parseAuthenticatorAttachment(value: String, field: String): ValidationResult<AuthenticatorAttachment> {
        val parsed = when (value.lowercase()) {
            "platform" -> AuthenticatorAttachment.PLATFORM
            "cross-platform" -> AuthenticatorAttachment.CROSS_PLATFORM
            else -> null
        }

        return if (parsed != null) {
            ValidationResult.Valid(parsed)
        } else {
            ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = field,
                        message = "Unknown authenticatorAttachment value: $value",
                    ),
                ),
            )
        }
    }

    private fun parseAttestationConveyancePreference(
        value: String,
        field: String,
    ): ValidationResult<AttestationConveyancePreference> {
        val parsed = AttestationConveyancePreference.entries.find { it.name.equals(value, ignoreCase = true) }
        return if (parsed != null) {
            ValidationResult.Valid(parsed)
        } else {
            ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = field,
                        message = "Unknown attestation value: $value",
                    ),
                ),
            )
        }
    }

    private fun parseAuthenticatorTransport(
        value: String,
        field: String,
    ): ValidationResult<AuthenticatorTransport> {
        val parsed = when (value.lowercase()) {
            "usb" -> AuthenticatorTransport.USB
            "nfc" -> AuthenticatorTransport.NFC
            "ble" -> AuthenticatorTransport.BLE
            "smart-card" -> AuthenticatorTransport.SMART_CARD
            "hybrid" -> AuthenticatorTransport.HYBRID
            "internal" -> AuthenticatorTransport.INTERNAL
            else -> null
        }

        return if (parsed != null) {
            ValidationResult.Valid(parsed)
        } else {
            ValidationResult.Invalid(
                listOf(
                    WebAuthnValidationError.InvalidValue(
                        field = field,
                        message = "Unknown authenticator transport: $value",
                    ),
                ),
            )
        }
    }

    private fun toModel(value: PrfValuesDto): dev.webauthn.model.AuthenticationExtensionsPRFValues {
        return toModelValidated(value, "extensions.prf").fold(
            onValid = { it },
            onInvalid = { errors ->
                throw IllegalArgumentException(errors.joinToString("; ") { "${it.field}: ${it.message}" })
            },
        )
    }

    private fun dev.webauthn.model.Base64UrlBytes.toBase64Url(): String = encoded()
}

private data class ParsedAuthenticatorData(
    val authenticatorData: dev.webauthn.model.AuthenticatorData,
    val attestedCredentialData: AttestedCredentialData?,
)

@OptIn(ExperimentalSerializationApi::class)
private val attestationObjectCbor = Cbor {
    ignoreUnknownKeys = true
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
private data class AttestationObjectCborDto(
    @SerialName("authData")
    @ByteString
    val authData: ByteArray? = null,
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

    val rpIdHash = dev.webauthn.model.RpIdHash.fromBytes(bytes.copyOfRange(0, 32))
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
        val aaguid = dev.webauthn.model.Aaguid.fromBytes(bytes.copyOfRange(offset, offset + 16))
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
            cosePublicKey = dev.webauthn.model.CosePublicKey.fromBytes(bytes.copyOfRange(offset, coseEnd)),
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

@OptIn(ExperimentalSerializationApi::class)
private fun extractAuthDataFromAttestationObject(attestationObject: ByteArray): ByteArray? {
    val itemEnd = skipCborItem(attestationObject, 0) ?: return null
    if (itemEnd != attestationObject.size) {
        return null
    }
    return runCatching {
        attestationObjectCbor.decodeFromByteArray<AttestationObjectCborDto>(attestationObject).authData
    }.getOrNull()
}

private const val FLAG_ATTESTED_CREDENTIAL_DATA: Int = 0x40

private inline fun <T, R> ValidationResult<T>.fold(
    onValid: (T) -> R,
    onInvalid: (List<WebAuthnValidationError>) -> R,
): R {
    return when (this) {
        is ValidationResult.Valid -> onValid(value)
        is ValidationResult.Invalid -> onInvalid(errors)
    }
}
