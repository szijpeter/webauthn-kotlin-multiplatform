package smoke.server

import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.ktor.AuthenticationFinishPayload
import dev.webauthn.server.ktor.RegistrationFinishPayload
import dev.webauthn.server.ktor.installWebAuthnRoutes
import dev.webauthn.server.store.exposed.ExposedCredentialStore
import dev.webauthn.server.store.exposed.initializeWebAuthnSchema
import io.ktor.server.application.Application
import io.ktor.server.routing.Route
import org.jetbrains.exposed.v1.jdbc.Database

fun Application.installPublishedWebAuthnApi(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
) {
    installWebAuthnRoutes(registrationService, authenticationService)
}

fun Route.acceptPublishedPayloads(
    registration: RegistrationFinishPayload,
    authentication: AuthenticationFinishPayload,
) {
    registration.response
    authentication.response
}

fun publishedStoreApi(database: Database): ExposedCredentialStore {
    initializeWebAuthnSchema(database)
    return ExposedCredentialStore(database)
}
