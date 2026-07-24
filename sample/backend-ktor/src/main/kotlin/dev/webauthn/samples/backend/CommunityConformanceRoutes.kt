package dev.webauthn.samples.backend

import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.WebAuthnDtoMapper
import dev.webauthn.server.RegistrationFinishRequest
import dev.webauthn.server.RegistrationService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

public data class CommunityConformanceConfig(
    val rpId: String,
    val rpName: String,
    val origin: String,
)

public fun Application.installCommunityConformanceRoutes(
    registrationService: RegistrationService,
    config: CommunityConformanceConfig,
) {
    routing {
        post("/attestation/options") {
            call.handleAttestationOptions(registrationService, config)
        }

        post("/attestation/result") {
            call.handleAttestationResult(registrationService)
        }
    }
}

private suspend fun ApplicationCall.handleAttestationOptions(
    registrationService: RegistrationService,
    config: CommunityConformanceConfig,
) {
    val payload = receive<JsonObject>()
    val username = payload.stringValue("username")
        ?: payload.stringValue("userName")
        ?: return respondConformanceError(HttpStatusCode.BadRequest, "Missing username")
    val request = payload.toRegistrationStartRequest(username, config)
    val options = registrationService.start(request)
    val optionsJson = conformanceJson.encodeToJsonElement(
        serializer = PublicKeyCredentialCreationOptionsDto.serializer(),
        value = WebAuthnDtoMapper.fromModel(options),
    ).jsonObject

    respond(HttpStatusCode.OK, payload.communityOptionsResponse(optionsJson))
}

private suspend fun ApplicationCall.handleAttestationResult(
    registrationService: RegistrationService,
) {
    val payload = receive<JsonObject>()
    val response = payload.parseRegistrationResponseDto()
        ?: return respondConformanceError(HttpStatusCode.BadRequest, "Invalid registration response")
    val clientData = payload.parseClientData(response)
        ?: return respondConformanceError(HttpStatusCode.BadRequest, "Invalid clientDataJSON")

    when (
        val result = registrationService.finish(
            RegistrationFinishRequest(
                responseDto = response,
                clientData = clientData,
            ),
        )
    ) {
        is ValidationResult.Valid -> respondConformanceRegistrationSuccess(result)
        is ValidationResult.Invalid -> respondConformanceError(
            HttpStatusCode.BadRequest,
            result.errors.joinToString("; ") { "${it.field}: ${it.message}" },
        )
    }
}

private suspend fun ApplicationCall.respondConformanceRegistrationSuccess(
    result: ValidationResult.Valid<RegistrationResponse>,
) {
    respond(
        HttpStatusCode.OK,
        mapOf(
            "status" to "ok",
            "errorMessage" to "",
            "credentialId" to result.value.credentialId.value.encoded(),
        ),
    )
}

private suspend fun ApplicationCall.respondConformanceError(
    status: HttpStatusCode,
    message: String,
) {
    respond(
        status,
        mapOf(
            "status" to "failed",
            "errorMessage" to message,
            "errors" to [message],
        ),
    )
}
