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
import dev.webauthn.model.getOrNull
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
                ValidationResult.Valid(
                    RegistrationResponse(
                        credentialId = credentialId.value,
                        clientDataJson = (clientData as ValidationResult.Valid).value,
                        attestationObject = (attestation as ValidationResult.Valid).value,
                        rawAuthenticatorData = dev.webauthn.model.AuthenticatorData(ByteArray(32), 0, 0),
                        attestedCredentialData = AttestedCredentialData(
                            credentialId = credentialId.value,
                            cosePublicKey = ByteArray(0),
                        ),
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
                if (clientData is ValidationResult.Invalid) {
                    return clientData
                }
                if (signature is ValidationResult.Invalid) {
                    return signature
                }
                ValidationResult.Valid(
                    AuthenticationResponse(
                        credentialId = credentialId.value,
                        clientDataJson = (clientData as ValidationResult.Valid).value,
                        authenticatorData = dev.webauthn.model.AuthenticatorData(ByteArray(32), 0, 0),
                        signature = (signature as ValidationResult.Valid).value,
                        userHandle = value.response.userHandle?.let { UserHandle.parse(it).getOrNull() },
                    ),
                )
            }
        }
    }
}

private inline fun <T, R> ValidationResult<T>.fold(
    onValid: (T) -> R,
    onInvalid: (List<WebAuthnValidationError>) -> R,
): R {
    return when (this) {
        is ValidationResult.Valid -> onValid(value)
        is ValidationResult.Invalid -> onInvalid(errors)
    }
}
