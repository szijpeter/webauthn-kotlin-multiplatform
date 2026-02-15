package dev.webauthn.server.ktor

import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.getOrThrow
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import dev.webauthn.server.AuthenticationFinishRequest
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.AuthenticationStartRequest
import dev.webauthn.server.RegistrationFinishRequest
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.RegistrationStartRequest
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable

@Serializable
public data class RegistrationStartPayload(
    public val rpId: String,
    public val rpName: String,
    public val origin: String,
    public val userName: String,
    public val userDisplayName: String,
    public val userHandle: String,
    public val extensions: dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String,
    public val extensions: dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
public data class RegistrationFinishPayload(
    public val response: RegistrationResponseDto,
    public val clientDataType: String,
    public val challenge: String,
    public val origin: String,
)

@Serializable
public data class AuthenticationFinishPayload(
    public val response: AuthenticationResponseDto,
    public val clientDataType: String,
    public val challenge: String,
    public val origin: String,
)

public fun Application.installWebAuthnRoutes(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
): Unit {
    routing {
        webAuthnRoutes(registrationService, authenticationService)
    }
}

public fun Route.webAuthnRoutes(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
): Unit {
    route("/webauthn") {
        post("/registration/start") {
            val payload = call.receive<RegistrationStartPayload>()
            val extensions = payload.extensions?.let {
                when (val parsed = WebAuthnDtoMapper.toModelValidated(it, fieldPrefix = "extensions")) {
                    is dev.webauthn.model.ValidationResult.Valid -> parsed.value
                    is dev.webauthn.model.ValidationResult.Invalid -> {
                        call.respond(HttpStatusCode.BadRequest, mapOf("errors" to parsed.errors.map { err -> err.message }))
                        return@post
                    }
                }
            }
            val options = registrationService.start(
                RegistrationStartRequest(
                    rpId = RpId.parseOrThrow(payload.rpId),
                    rpName = payload.rpName,
                    origin = Origin.parseOrThrow(payload.origin),
                    userName = payload.userName,
                    userDisplayName = payload.userDisplayName,
                    userHandle = UserHandle.parse(payload.userHandle).getOrThrow(),
                    extensions = extensions,
                ),
            )
            call.respond(HttpStatusCode.OK, WebAuthnDtoMapper.fromModel(options))
        }

        post("/registration/finish") {
            val payload = call.receive<RegistrationFinishPayload>()
            val request = RegistrationFinishRequest(
                responseDto = payload.response,
                clientData = CollectedClientData(
                    type = payload.clientDataType,
                    challenge = Challenge.parseOrThrow(payload.challenge),
                    origin = Origin.parseOrThrow(payload.origin),
                ),
            )
            when (val result = registrationService.finish(request)) {
                is dev.webauthn.model.ValidationResult.Valid -> {
                    call.respond(HttpStatusCode.OK, mapOf("status" to "ok", "credentialId" to result.value.credentialId.value.encoded()))
                }

                is dev.webauthn.model.ValidationResult.Invalid -> {
                    call.respond(HttpStatusCode.BadRequest, mapOf("errors" to result.errors.map { it.message }))
                }
            }
        }

        post("/authentication/start") {
            val payload = call.receive<AuthenticationStartPayload>()
            val extensions = payload.extensions?.let {
                when (val parsed = WebAuthnDtoMapper.toModelValidated(it, fieldPrefix = "extensions")) {
                    is dev.webauthn.model.ValidationResult.Valid -> parsed.value
                    is dev.webauthn.model.ValidationResult.Invalid -> {
                        call.respond(HttpStatusCode.BadRequest, mapOf("errors" to parsed.errors.map { err -> err.message }))
                        return@post
                    }
                }
            }
            val result = authenticationService.start(
                AuthenticationStartRequest(
                    rpId = RpId.parseOrThrow(payload.rpId),
                    origin = Origin.parseOrThrow(payload.origin),
                    userName = payload.userName,
                    extensions = extensions,
                ),
            )
            when (result) {
                is dev.webauthn.model.ValidationResult.Valid -> {
                    call.respond(HttpStatusCode.OK, WebAuthnDtoMapper.fromModel(result.value))
                }

                is dev.webauthn.model.ValidationResult.Invalid -> {
                    call.respond(HttpStatusCode.BadRequest, mapOf("errors" to result.errors.map { it.message }))
                }
            }
        }

        post("/authentication/finish") {
            val payload = call.receive<AuthenticationFinishPayload>()
            val request = AuthenticationFinishRequest(
                responseDto = payload.response,
                clientData = CollectedClientData(
                    type = payload.clientDataType,
                    challenge = Challenge.parseOrThrow(payload.challenge),
                    origin = Origin.parseOrThrow(payload.origin),
                ),
            )

            when (val result = authenticationService.finish(request)) {
                is dev.webauthn.model.ValidationResult.Valid -> {
                    call.respond(HttpStatusCode.OK, mapOf("status" to "ok", "credentialId" to result.value.credentialId.value.encoded()))
                }

                is dev.webauthn.model.ValidationResult.Invalid -> {
                    call.respond(HttpStatusCode.BadRequest, mapOf("errors" to result.errors.map { it.message }))
                }
            }
        }
    }
}
