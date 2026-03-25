@file:Suppress("UndocumentedPublicClass")
@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package dev.webauthn.serialization

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonTransformingSerializer

private const val PUBLIC_KEY_CREDENTIAL_DTO_TYPE = "public-key"

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
    @SerialName("excludeCredentials")
    public val excludeCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
    @SerialName("authenticatorSelection") public val authenticatorSelection: AuthenticatorSelectionCriteriaDto? = null,
    @SerialName("attestation") public val attestation: String? = null,
    @SerialName("extensions") public val extensions: AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
public data class PublicKeyCredentialRequestOptionsDto(
    @SerialName("challenge") public val challenge: String,
    @SerialName("rpId") public val rpId: String? = null,
    @SerialName("timeout") public val timeoutMs: Long? = null,
    @SerialName("allowCredentials")
    @Serializable(with = NullAsEmptyCredentialDescriptorListSerializer::class)
    public val allowCredentials: List<PublicKeyCredentialDescriptorDto> = emptyList(),
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
    @SerialName("id") public val id: String? = null,
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
    @SerialName("clientExtensionResults")
    public val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
    @EncodeDefault(mode = EncodeDefault.Mode.ALWAYS)
    @SerialName("type") public val type: String = PUBLIC_KEY_CREDENTIAL_DTO_TYPE,
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
    @SerialName("clientExtensionResults")
    public val clientExtensionResults: AuthenticationExtensionsClientOutputsDto? = null,
    @EncodeDefault(mode = EncodeDefault.Mode.ALWAYS)
    @SerialName("type") public val type: String = PUBLIC_KEY_CREDENTIAL_DTO_TYPE,
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

internal object NullAsEmptyCredentialDescriptorListSerializer :
    JsonTransformingSerializer<List<PublicKeyCredentialDescriptorDto>>(
        ListSerializer(PublicKeyCredentialDescriptorDto.serializer()),
    ) {
    override fun transformDeserialize(element: JsonElement): JsonElement {
        return if (element is JsonNull) JsonArray(emptyList()) else element
    }
}
