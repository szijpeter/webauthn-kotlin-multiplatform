package dev.webauthn.server.ktor

import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import dev.webauthn.model.getOrThrow
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import dev.webauthn.server.AuthenticationFinishRequest
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.AuthenticationStartRequest
import dev.webauthn.server.RegistrationFinishRequest
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.RegistrationStartRequest
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
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
/** Request payload for registration-start HTTP endpoint. */
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
/** Request payload for authentication-start HTTP endpoint. */
public data class AuthenticationStartPayload(
    public val rpId: String,
    public val origin: String,
    public val userName: String,
    public val userHandle: String? = null,
    public val extensions: dev.webauthn.serialization.AuthenticationExtensionsClientInputsDto? = null,
)

@Serializable
/** Request payload for registration-finish HTTP endpoint. */
public data class RegistrationFinishPayload(
    public val response: RegistrationResponseDto,
    public val clientDataType: String,
    public val challenge: String,
    public val origin: String,
)

@Serializable
/** Request payload for authentication-finish HTTP endpoint. */
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

@Suppress("LongMethod")
public fun Route.webAuthnRoutes(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
): Unit {
    route("/webauthn") {
        post("/registration/start") {
            val payload = call.receive<RegistrationStartPayload>()
            val extensions = when (
                val parsed = call.parseExtensionsOrReject(
                    payload.extensions,
                    operation = "webauthn.registration.start",
                )
            ) {
                is ParsedExtensionsResult.Accepted -> parsed.value
                ParsedExtensionsResult.Rejected -> return@post
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
            call.respondValidationResult(
                operation = "webauthn.registration.finish",
                result = registrationService.finish(request),
            ) { result ->
                call.respond(
                    HttpStatusCode.OK,
                    mapOf("status" to "ok", "credentialId" to result.credentialId.value.encoded()),
                )
            }
        }

        post("/authentication/start") {
            val payload = call.receive<AuthenticationStartPayload>()
            val extensions = when (
                val parsed = call.parseExtensionsOrReject(
                    payload.extensions,
                    operation = "webauthn.authentication.start",
                )
            ) {
                is ParsedExtensionsResult.Accepted -> parsed.value
                ParsedExtensionsResult.Rejected -> return@post
            }
            call.respondValidationResult(
                operation = "webauthn.authentication.start",
                result = authenticationService.start(
                    AuthenticationStartRequest(
                        rpId = RpId.parseOrThrow(payload.rpId),
                        origin = Origin.parseOrThrow(payload.origin),
                        userName = payload.userName,
                        extensions = extensions,
                    ),
                ),
            ) { result ->
                call.respond(HttpStatusCode.OK, WebAuthnDtoMapper.fromModel(result))
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

            call.respondValidationResult(
                operation = "webauthn.authentication.finish",
                result = authenticationService.finish(request),
            ) { result ->
                call.respond(
                    HttpStatusCode.OK,
                    mapOf("status" to "ok", "credentialId" to result.credentialId.value.encoded()),
                )
            }
        }
    }
}

private sealed interface ParsedExtensionsResult {
    data class Accepted(
        val value: dev.webauthn.model.AuthenticationExtensionsClientInputs?,
    ) : ParsedExtensionsResult

    data object Rejected : ParsedExtensionsResult
}

private suspend fun ApplicationCall.parseExtensionsOrReject(
    extensions: AuthenticationExtensionsClientInputsDto?,
    operation: String,
): ParsedExtensionsResult {
    if (extensions == null) {
        return ParsedExtensionsResult.Accepted(null)
    }
    return when (val parsed = WebAuthnDtoMapper.toModelValidated(extensions, fieldPrefix = "extensions")) {
        is ValidationResult.Valid -> ParsedExtensionsResult.Accepted(parsed.value)
        is ValidationResult.Invalid -> {
            respondValidationFailure(operation, parsed.errors)
            ParsedExtensionsResult.Rejected
        }
    }
}

private suspend inline fun <T> ApplicationCall.respondValidationResult(
    operation: String,
    result: ValidationResult<T>,
    onValid: suspend (T) -> Unit,
) {
    when (result) {
        is ValidationResult.Valid -> onValid(result.value)
        is ValidationResult.Invalid -> respondValidationFailure(operation, result.errors)
    }
}

private suspend fun ApplicationCall.respondValidationFailure(
    operation: String,
    errors: List<WebAuthnValidationError>,
) {
    val encodedErrors = errors.map { "${it.field}: ${it.message}" }
    application.environment.log.warn("$operation rejected: ${encodedErrors.joinToString("; ")}")
    respond(HttpStatusCode.BadRequest, mapOf("errors" to encodedErrors))
}
