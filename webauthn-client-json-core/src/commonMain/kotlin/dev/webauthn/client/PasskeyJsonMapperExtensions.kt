@file:Suppress("UndocumentedPublicFunction")

package dev.webauthn.client

import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper

@Throws(IllegalArgumentException::class)
public fun PasskeyJsonMapper.encodeCreationOptionsOrThrowInvalid(options: PublicKeyCredentialCreationOptions): String {
    return fromMapperInvalidOptions("Failed to encode registration options JSON") {
        val dto = WebAuthnDtoMapper.fromModel(options)
        encode(dto, PublicKeyCredentialCreationOptionsDto.serializer())
    }
}

@Throws(IllegalArgumentException::class)
public fun PasskeyJsonMapper.encodeAssertionOptionsOrThrowInvalid(options: PublicKeyCredentialRequestOptions): String {
    return fromMapperInvalidOptions("Failed to encode authentication options JSON") {
        val dto = WebAuthnDtoMapper.fromModel(options)
        encode(dto, PublicKeyCredentialRequestOptionsDto.serializer())
    }
}

@Throws(IllegalArgumentException::class)
public fun PasskeyJsonMapper.decodeCreationOptionsOrThrowInvalid(payload: String): PublicKeyCredentialCreationOptions {
    val validation = fromMapperInvalidOptions("Failed to parse registration options JSON") {
        val dto = decode(payload, PublicKeyCredentialCreationOptionsDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalArgumentException(message) }
}

@Throws(IllegalArgumentException::class)
public fun PasskeyJsonMapper.decodeAssertionOptionsOrThrowInvalid(payload: String): PublicKeyCredentialRequestOptions {
    val validation = fromMapperInvalidOptions("Failed to parse authentication options JSON") {
        val dto = decode(payload, PublicKeyCredentialRequestOptionsDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalArgumentException(message) }
}

@Throws(IllegalStateException::class)
public fun PasskeyJsonMapper.encodeRegistrationResponse(response: RegistrationResponse): String {
    return fromMapperPlatformResponse("Failed to encode registration response JSON") {
        val dto = WebAuthnDtoMapper.fromModel(response)
        encode(dto, RegistrationResponseDto.serializer())
    }
}

@Throws(IllegalStateException::class)
public fun PasskeyJsonMapper.decodeRegistrationResponseOrThrowPlatform(payload: String): RegistrationResponse {
    val validation = fromMapperPlatformResponse("Failed to parse registration response JSON") {
        val dto = decode(payload, RegistrationResponseDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalStateException(message) }
}

@Throws(IllegalStateException::class)
public fun PasskeyJsonMapper.encodeAuthenticationResponse(response: AuthenticationResponse): String {
    return fromMapperPlatformResponse("Failed to encode authentication response JSON") {
        val dto = WebAuthnDtoMapper.fromModel(response)
        encode(dto, AuthenticationResponseDto.serializer())
    }
}

@Throws(IllegalStateException::class)
public fun PasskeyJsonMapper.decodeAuthenticationResponseOrThrowPlatform(payload: String): AuthenticationResponse {
    val validation = fromMapperPlatformResponse("Failed to parse authentication response JSON") {
        val dto = decode(payload, AuthenticationResponseDto.serializer())
        WebAuthnDtoMapper.toModel(dto)
    }
    return validation.toValueOrThrow { message -> IllegalStateException(message) }
}
