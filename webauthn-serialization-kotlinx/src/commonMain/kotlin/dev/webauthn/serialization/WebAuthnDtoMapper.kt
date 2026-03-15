@file:Suppress("MaxLineLength")

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
 * Maps between wire DTOs and strict WebAuthn model types with validation aggregation.
 */
@Suppress("LargeClass", "TooManyFunctions")
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

    @Suppress("CyclomaticComplexMethod", "LongMethod")
    public fun toModel(value: PublicKeyCredentialCreationOptionsDto): ValidationResult<PublicKeyCredentialCreationOptions> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val rpId = value.rp.id?.let { encodedRpId ->
            RpId.parse(encodedRpId).fold(
                onValid = { it },
                onInvalid = { errors += it; null },
            )
        } ?: run {
            errors += WebAuthnValidationError.MissingValue(field = "rp.id", message = "RP ID is required")
            null
        }
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
            if (descriptor.type != "public-key") {
                return@mapNotNull null
            }
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

        val residentKey = when (val wireValue = value.authenticatorSelection?.residentKey) {
            null -> if (value.authenticatorSelection?.requireResidentKey == true) {
                ResidentKeyRequirement.REQUIRED
            } else {
                ResidentKeyRequirement.DISCOURAGED
            }
            else -> {
                ResidentKeyRequirement.entries.find { it.name.equals(wireValue, ignoreCase = true) } ?: run {
                    errors += WebAuthnValidationError.InvalidValue(
                        field = "authenticatorSelection.residentKey",
                        message = "Unknown residentKey value: $wireValue",
                    )
                    null
                }
            }
        }
        val userVerification = when (val wireValue = value.authenticatorSelection?.userVerification) {
            null -> UserVerificationRequirement.PREFERRED
            else -> {
                UserVerificationRequirement.entries.find {
                    it.name.equals(wireValue, ignoreCase = true)
                } ?: run {
                    errors += WebAuthnValidationError.InvalidValue(
                        field = "authenticatorSelection.userVerification",
                        message = "Unknown userVerification value: $wireValue",
                    )
                    null
                }
            }
        }
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

        if (errors.isNotEmpty() || residentKey == null || userVerification == null) {
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
            rpId = value.rpId?.value,
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

    @Suppress("CyclomaticComplexMethod", "LongMethod")
    public fun toModel(value: PublicKeyCredentialRequestOptionsDto): ValidationResult<PublicKeyCredentialRequestOptions> {
        val errors = mutableListOf<WebAuthnValidationError>()

        val challenge = Challenge.parse(value.challenge).fold(
            onValid = { it },
            onInvalid = { errors += it; null },
        )
        val rpId = value.rpId?.let { encodedRpId ->
            RpId.parse(encodedRpId).fold(
                onValid = { it },
                onInvalid = { errors += it; null },
            )
        }

        val allowCredentials = value.allowCredentials.mapNotNull { descriptor ->
            if (descriptor.type != "public-key") {
                return@mapNotNull null
            }
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

        if (challenge == null || errors.isNotEmpty()) {
            return ValidationResult.Invalid(errors)
        }

        val userVerification = UserVerificationRequirement.entries.find {
            it.name.equals(value.userVerification, ignoreCase = true)
        } ?: run {
            errors += WebAuthnValidationError.InvalidValue(
                field = "userVerification",
                message = "Unknown userVerification value: ${value.userVerification}",
            )
            null
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

        if (errors.isNotEmpty() || userVerification == null) {
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

    @Suppress("LongMethod")
    public fun toModel(value: RegistrationResponseDto): ValidationResult<RegistrationResponse> {
        val credentialId = parseMatchingCredentialId(value.id, value.rawId)
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
                if (attestedCredentialData.credentialId != credentialId.value) {
                    return ValidationResult.Invalid(
                        listOf(
                            WebAuthnValidationError.InvalidFormat(
                                field = "id/rawId",
                                message = "id/rawId must match attested credential ID",
                            ),
                        ),
                    )
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
                    RegistrationResponse(
                        credentialId = attestedCredentialData.credentialId,
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

    @Suppress("CyclomaticComplexMethod")
    public fun toModel(value: AuthenticationResponseDto): ValidationResult<AuthenticationResponse> {
        val credentialId = parseMatchingCredentialId(value.id, value.rawId)
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

    @Suppress("CyclomaticComplexMethod")
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

private fun parseMatchingCredentialId(id: String, rawId: String): ValidationResult<CredentialId> {
    val parsedId = CredentialId.parse(id)
    if (parsedId is ValidationResult.Invalid) {
        return parsedId
    }

    val parsedRawId = CredentialId.parse(rawId)
    if (parsedRawId is ValidationResult.Invalid) {
        return parsedRawId
    }

    val idValue = (parsedId as ValidationResult.Valid).value
    val rawIdValue = (parsedRawId as ValidationResult.Valid).value
    return if (idValue == rawIdValue) {
        ValidationResult.Valid(idValue)
    } else {
        ValidationResult.Invalid(
            listOf(
                WebAuthnValidationError.InvalidFormat(
                    field = "id/rawId",
                    message = "id and rawId must match",
                ),
            ),
        )
    }
}

@Suppress("MagicNumber")
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
